<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\MobileId;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\EcdsaSignature;
use Allkiri\Crypto\KeyPair;
use Allkiri\Crypto\KeyType;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Http\HttpRequest;
use Allkiri\Http\HttpResponse;
use Allkiri\MobileId\MobileIdConfiguration;
use Allkiri\MobileId\MobileIdResult;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Tests\Support\Pki\TestPki;

/**
 * An in-process Mobile-ID service for offline tests.
 *
 * It cannot sign a bare digest, because neither phpseclib nor OpenSSL will
 * sign one without hashing it first. So the test hands it the preimage — the
 * challenge, or the canonical SignedInfo — and the mock checks that the hash
 * it was sent really is that preimage's digest before signing it. The result
 * is byte-for-byte what a phone would have produced.
 */
final class MockMobileIdService
{
    public const URL = 'https://mid.allkiri.test/mid-api';

    public MobileIdResult $result = MobileIdResult::Ok;

    public bool $certificateFound = true;

    /** How many times a status request answers RUNNING before completing. */
    public int $runningPolls = 0;

    /** ECDSA values come back DER-encoded from the real service. */
    public bool $derEncodeEcdsa = true;

    public bool $corruptSignature = false;

    public bool $omitSignature = false;

    public ?string $algorithmName = null;

    /** @var array<string, string> hex digest => the bytes it is a digest of */
    private array $preimages = [];

    /** @var array<string, array{type: string, hash: string, hashType: string, polls: int}> */
    private array $sessions = [];

    /** @var list<array<string, mixed>> every request body the service received */
    public array $received = [];

    private int $nextSession = 1;

    public function __construct(
        private readonly KeyPair $signer,
        private readonly string $url = self::URL,
    ) {}

    public static function register(MockHttpClient $http, ?KeyPair $signer = null, string $url = self::URL): self
    {
        $mock = new self($signer ?? TestPki::signerEc256(), $url);
        $http->on($url, $mock->handle(...));

        return $mock;
    }

    public function configuration(): MobileIdConfiguration
    {
        return new MobileIdConfiguration($this->url, MobileIdConfiguration::DEMO_RELYING_PARTY_UUID, 'TEST');
    }

    public function certificate(): Certificate
    {
        return $this->signer->certificate;
    }

    /**
     * Tell the mock what the next hash it is sent will be a digest of.
     */
    public function expectToSign(string $preimage): self
    {
        foreach (['sha256', 'sha384', 'sha512'] as $algorithm) {
            $this->preimages[bin2hex(hash($algorithm, $preimage, true))] = $preimage;
        }

        return $this;
    }

    public function handle(HttpRequest $request): HttpResponse
    {
        $path = (string) parse_url($request->url, PHP_URL_PATH);
        $path = substr($path, \strlen((string) parse_url($this->url, PHP_URL_PATH)));

        if ($request->method === 'POST') {
            /** @var array<string, mixed> $body */
            $body = json_decode($request->body, true);
            $this->received[] = $body;

            return match ($path) {
                '/certificate' => $this->certificateResponse(),
                '/authentication' => $this->startResponse('authentication', $body),
                '/signature' => $this->startResponse('signature', $body),
                default => self::json(404, ['error' => 'no such endpoint ' . $path]),
            };
        }

        if (preg_match('#^/(authentication|signature)/session/([^/?]+)#', $path, $matches) === 1) {
            return $this->statusResponse($matches[2]);
        }

        return self::json(404, ['error' => 'no such endpoint ' . $path]);
    }

    private function certificateResponse(): HttpResponse
    {
        if (!$this->certificateFound) {
            return self::json(200, ['result' => 'NOT_FOUND']);
        }

        return self::json(200, ['result' => 'OK', 'cert' => $this->signer->certificate->base64()]);
    }

    /**
     * @param array<string, mixed> $body
     */
    private function startResponse(string $type, array $body): HttpResponse
    {
        $encoded = $body['hash'] ?? null;
        $decoded = \is_string($encoded) ? base64_decode($encoded, true) : false;
        $hash = $decoded === false ? '' : $decoded;
        $sessionId = \sprintf('%08x-0000-0000-0000-%012d', crc32($type), $this->nextSession++);
        $this->sessions[$sessionId] = [
            'type' => $type,
            'hash' => $hash,
            'hashType' => \is_string($body['hashType'] ?? null) ? $body['hashType'] : 'SHA256',
            'polls' => 0,
        ];

        return self::json(200, ['sessionID' => $sessionId]);
    }

    private function statusResponse(string $sessionId): HttpResponse
    {
        $session = $this->sessions[$sessionId] ?? null;
        if ($session === null) {
            return self::json(404, ['error' => 'session not found']);
        }
        if ($session['polls'] < $this->runningPolls) {
            ++$this->sessions[$sessionId]['polls'];

            return self::json(200, ['state' => 'RUNNING']);
        }
        if ($this->result !== MobileIdResult::Ok) {
            return self::json(200, ['state' => 'COMPLETE', 'result' => $this->result->value]);
        }

        $response = ['state' => 'COMPLETE', 'result' => 'OK'];
        if (!$this->omitSignature) {
            $algorithm = $this->algorithmFor($session['hashType']);
            $response['signature'] = [
                'value' => base64_encode($this->sign($session['hash'], $algorithm)),
                'algorithm' => $this->algorithmName ?? \sprintf(
                    '%sWith%sEncryption',
                    $algorithm->hash()->name(),
                    $algorithm->keyType() === KeyType::EC ? 'EC' : 'RSA',
                ),
            ];
        }
        if ($session['type'] === 'authentication') {
            $response['cert'] = $this->signer->certificate->base64();
        }

        return self::json(200, $response);
    }

    private function algorithmFor(string $hashType): SignatureAlgorithm
    {
        $bits = match (strtoupper($hashType)) {
            'SHA384' => '384',
            'SHA512' => '512',
            default => '256',
        };

        return SignatureAlgorithm::from(($this->signer->privateKey->keyType() === KeyType::EC ? 'ES' : 'RS') . $bits);
    }

    private function sign(string $hash, SignatureAlgorithm $algorithm): string
    {
        $preimage = $this->preimages[bin2hex($hash)]
            ?? throw new \LogicException('The mock was asked to sign a hash it has no preimage for; call expectToSign() first');

        // PrivateKey::sign emits the XML-DSig wire format, so ECDSA comes back
        // as r‖s; the real service DER-encodes it.
        $signature = $this->signer->privateKey->sign($algorithm, $preimage);
        if ($this->derEncodeEcdsa && $algorithm->keyType() === KeyType::EC) {
            $signature = EcdsaSignature::rawToDer($signature);
        }
        if ($this->corruptSignature) {
            $signature[\strlen($signature) - 1] = \chr(\ord($signature[\strlen($signature) - 1]) ^ 0xFF);
        }

        return $signature;
    }

    /**
     * @param array<string, mixed> $body
     */
    private static function json(int $status, array $body): HttpResponse
    {
        return new HttpResponse($status, ['Content-Type' => 'application/json'], json_encode($body, JSON_THROW_ON_ERROR));
    }
}
