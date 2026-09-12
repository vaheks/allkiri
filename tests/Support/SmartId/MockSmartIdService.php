<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\SmartId;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\KeyPair;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Http\HttpRequest;
use Allkiri\Http\HttpResponse;
use Allkiri\SmartId\AcspV2Payload;
use Allkiri\SmartId\CertificateLevel;
use Allkiri\SmartId\DeviceLink;
use Allkiri\SmartId\FlowType;
use Allkiri\SmartId\InteractionType;
use Allkiri\SmartId\SmartIdConfiguration;
use Allkiri\SmartId\SmartIdEndResult;
use Allkiri\SmartId\VerificationCode;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Tests\Support\Pki\TestPki;

/**
 * An in-process Smart-ID RP API v3 for offline tests.
 *
 * Authentication needs no help: the mock assembles the ACSP_V2 payload from the
 * request exactly as the real service does, and signs that, so the payload
 * construction is genuinely exercised rather than assumed.
 *
 * Signing does need help, because neither phpseclib nor OpenSSL will sign a
 * bare digest without hashing it first. The test hands over the preimage — the
 * canonical SignedInfo — and the mock checks the digest it was sent really is
 * that preimage's before signing it.
 */
final class MockSmartIdService
{
    public const URL = 'https://sid.allkiri.test/smart-id-rp/v3';

    public const DOCUMENT_NUMBER = 'PNOEE-40504040001-MOCK-Q';

    public SmartIdEndResult $endResult = SmartIdEndResult::Ok;

    public ?InteractionType $refusedInteraction = null;

    /** How many times a status request answers RUNNING before completing. */
    public int $runningPolls = 0;

    public bool $certificateFound = true;

    public bool $corruptSignature = false;

    public CertificateLevel $certificateLevel = CertificateLevel::Qualified;

    public FlowType $flowType = FlowType::Notification;

    /** Which dialogue the app claims it showed; the first offered one by default. */
    public ?InteractionType $interactionTypeUsed = null;

    /** Knobs for parameters no XML-DSig signature method can describe. */
    public ?int $saltLengthOverride = null;

    public ?HashAlgorithm $maskHashOverride = null;

    public ?string $trailerFieldOverride = null;

    /** Answer with the deprecated PKCS#1 v1.5 algorithm instead of PSS. */
    public bool $legacyRsa = false;

    public ?string $serverRandomOverride = null;

    /** The shape of code a signature session reports. */
    public string $verificationCodeType = 'numeric4';

    /** @var array<string, string> hex digest => the bytes it is a digest of */
    private array $preimages = [];

    /** @var array<string, MockSession> */
    private array $sessions = [];

    /** @var list<array{path: string, body: array<string, mixed>}> */
    public array $received = [];

    private int $nextSession = 1;

    public function __construct(
        private readonly KeyPair $signer,
        private readonly string $url = self::URL,
    ) {}

    public static function register(MockHttpClient $http, ?KeyPair $signer = null, string $url = self::URL): self
    {
        $mock = new self($signer ?? TestPki::signerRsaPerson(), $url);
        $http->on($url, $mock->handle(...));

        return $mock;
    }

    public function configuration(): SmartIdConfiguration
    {
        return new SmartIdConfiguration(
            $this->url,
            SmartIdConfiguration::DEMO_RELYING_PARTY_UUID,
            'TEST',
            SmartIdConfiguration::SCHEME_DEMO,
        );
    }

    public function certificate(): Certificate
    {
        return $this->signer->certificate;
    }

    /**
     * Tell the mock what the next digest it is sent will be a digest of.
     */
    public function expectToSign(string $preimage): self
    {
        foreach (['sha256', 'sha384', 'sha512'] as $algorithm) {
            $this->preimages[bin2hex(hash($algorithm, $preimage, true))] = $preimage;
        }

        return $this;
    }

    /**
     * The last request body sent to a path containing this fragment.
     *
     * @return array<string, mixed>
     */
    public function lastRequestTo(string $pathFragment): array
    {
        foreach (array_reverse($this->received) as $entry) {
            if (str_contains($entry['path'], $pathFragment)) {
                return $entry['body'];
            }
        }

        throw new \LogicException('No request was made to a path containing ' . $pathFragment);
    }

    public function handle(HttpRequest $request): HttpResponse
    {
        $path = (string) parse_url($request->url, PHP_URL_PATH);
        $path = substr($path, \strlen((string) parse_url($this->url, PHP_URL_PATH)));

        if ($request->method === 'POST') {
            $decoded = json_decode($request->body, true);
            /** @var array<string, mixed> $body */
            $body = \is_array($decoded) ? $decoded : [];
            $this->received[] = ['path' => $path, 'body' => $body];

            if (str_starts_with($path, '/signature/certificate/')) {
                return $this->certificateResponse();
            }
            if (str_starts_with($path, '/signature/certificate-choice/notification/')) {
                return self::json(200, ['sessionID' => $this->newSession('cert', $body)]);
            }
            if (str_starts_with($path, '/authentication/device-link') || str_starts_with($path, '/signature/device-link')) {
                return $this->deviceLinkResponse(str_starts_with($path, '/authentication') ? 'auth' : 'sign', $body);
            }
            if (str_starts_with($path, '/authentication/notification') || str_starts_with($path, '/signature/notification')) {
                return $this->notificationResponse(str_starts_with($path, '/authentication') ? 'auth' : 'sign', $body);
            }

            return self::json(404, ['error' => 'no such endpoint ' . $path]);
        }

        if (preg_match('#^/session/([^/?]+)#', $path, $matches) === 1) {
            return $this->statusResponse($matches[1]);
        }

        return self::json(404, ['error' => 'no such endpoint ' . $path]);
    }

    // --- endpoints ----------------------------------------------------------

    private function certificateResponse(): HttpResponse
    {
        if (!$this->certificateFound) {
            return self::json(404, ['error' => 'no such account']);
        }

        return self::json(200, [
            'state' => 'OK',
            'cert' => ['value' => $this->signer->certificate->base64(), 'certificateLevel' => $this->certificateLevel->value],
        ]);
    }

    /**
     * @param array<string, mixed> $body
     */
    private function notificationResponse(string $type, array $body): HttpResponse
    {
        // The service requires vcType on an authentication and rejects the
        // request without it, and it answers with no verification code.
        if ($type === 'auth') {
            if (($body['vcType'] ?? null) !== 'numeric4') {
                return self::json(400, ['detail' => 'Null argument found: /vcType', 'paramName' => 'vcType']);
            }

            return self::json(200, ['sessionID' => $this->newSession($type, $body)]);
        }

        $sessionId = $this->newSession($type, $body);

        return self::json(200, [
            'sessionID' => $sessionId,
            'vc' => ['type' => $this->verificationCodeType, 'value' => VerificationCode::forData($this->sessions[$sessionId]->challenge)],
        ]);
    }

    /**
     * @param array<string, mixed> $body
     */
    private function deviceLinkResponse(string $type, array $body): HttpResponse
    {
        $sessionId = $this->newSession($type, $body);

        return self::json(200, [
            'sessionID' => $sessionId,
            'sessionToken' => 'token-' . $sessionId,
            'sessionSecret' => base64_encode(str_repeat("\x2a", 32)),
            'deviceLinkBase' => 'https://smart-id.test/dl',
        ]);
    }

    /**
     * @param array<string, mixed> $body
     */
    private function newSession(string $type, array $body): string
    {
        $sessionId = \sprintf('%s-0000-4000-8000-%012d', substr(md5($type), 0, 8), $this->nextSession++);

        $parameters = $body['signatureProtocolParameters'] ?? null;
        $encoded = \is_array($parameters) ? ($parameters['rpChallenge'] ?? $parameters['digest'] ?? null) : null;
        $decoded = \is_string($encoded) ? base64_decode($encoded, true) : false;

        $hashName = 'SHA-256';
        $algorithmParameters = \is_array($parameters) ? ($parameters['signatureAlgorithmParameters'] ?? null) : null;
        if (\is_array($algorithmParameters) && \is_string($algorithmParameters['hashAlgorithm'] ?? null)) {
            $hashName = $algorithmParameters['hashAlgorithm'];
        }

        $interactions = $body['interactions'] ?? null;
        $relyingPartyName = $body['relyingPartyName'] ?? null;

        $this->sessions[$sessionId] = new MockSession(
            $type,
            $decoded === false ? '' : $decoded,
            match (strtoupper($hashName)) {
                'SHA-384' => HashAlgorithm::SHA384,
                'SHA-512' => HashAlgorithm::SHA512,
                default => HashAlgorithm::SHA256,
            },
            \is_string($interactions) ? $interactions : '',
            \is_string($relyingPartyName) ? $relyingPartyName : '',
        );

        return $sessionId;
    }

    private function statusResponse(string $sessionId): HttpResponse
    {
        $session = $this->sessions[$sessionId] ?? null;
        if ($session === null) {
            return self::json(404, ['error' => 'session not found']);
        }
        if ($session->polls < $this->runningPolls) {
            ++$session->polls;

            return self::json(200, ['state' => 'RUNNING']);
        }

        if ($this->endResult !== SmartIdEndResult::Ok) {
            $result = ['endResult' => $this->endResult->value];
            if ($this->refusedInteraction !== null) {
                $result['details'] = ['interaction' => $this->refusedInteraction->value];
            }

            return self::json(200, ['state' => 'COMPLETE', 'result' => $result]);
        }

        return $session->type === 'auth'
            ? self::json(200, $this->authenticationStatus($session))
            : self::json(200, $this->signatureStatus($session));
    }

    // --- successful answers -------------------------------------------------

    /**
     * @return array<string, mixed>
     */
    private function authenticationStatus(MockSession $session): array
    {
        $serverRandom = $this->serverRandomOverride ?? base64_encode(str_repeat("\x07", 32));
        $used = $this->interactionTypeUsed ?? $session->firstInteraction();
        $userChallenge = $this->flowType->isDeviceLink()
            ? DeviceLink::base64Url(hash('sha256', 'user-challenge-' . $session->challenge, true))
            : null;

        $payload = new AcspV2Payload(
            SmartIdConfiguration::SCHEME_DEMO,
            $serverRandom,
            base64_encode($session->challenge),
            $userChallenge,
            base64_encode($session->relyingPartyName),
            null,
            base64_encode(hash('sha256', $session->interactions, true)),
            $used,
            $this->flowType,
        );

        $signature = [
            'value' => base64_encode($this->sign($payload->bytes(), $session->hashAlgorithm)),
            'serverRandom' => $serverRandom,
            'flowType' => $this->flowType->value,
        ] + $this->algorithmFields($session->hashAlgorithm);
        if ($userChallenge !== null) {
            $signature['userChallenge'] = $userChallenge;
        }

        return [
            'state' => 'COMPLETE',
            'result' => ['endResult' => 'OK', 'documentNumber' => self::DOCUMENT_NUMBER],
            'signatureProtocol' => AcspV2Payload::PROTOCOL,
            'signature' => $signature,
            'cert' => ['value' => $this->signer->certificate->base64(), 'certificateLevel' => $this->certificateLevel->value],
            'interactionTypeUsed' => $used->value,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function signatureStatus(MockSession $session): array
    {
        $preimage = $this->preimages[bin2hex($session->challenge)]
            ?? throw new \LogicException('The mock was asked to sign a digest it has no preimage for; call expectToSign() first');

        return [
            'state' => 'COMPLETE',
            'result' => ['endResult' => 'OK', 'documentNumber' => self::DOCUMENT_NUMBER],
            'signatureProtocol' => 'RAW_DIGEST_SIGNATURE',
            'signature' => [
                'value' => base64_encode($this->sign($preimage, $session->hashAlgorithm)),
                'flowType' => $this->flowType->value,
            ] + $this->algorithmFields($session->hashAlgorithm),
            'cert' => ['value' => $this->signer->certificate->base64(), 'certificateLevel' => $this->certificateLevel->value],
            'interactionTypeUsed' => ($this->interactionTypeUsed ?? $session->firstInteraction())->value,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function algorithmFields(HashAlgorithm $hash): array
    {
        if ($this->legacyRsa) {
            return ['signatureAlgorithm' => \sprintf('sha%dWithRSAEncryption', $hash->digestLength() * 8)];
        }

        return [
            'signatureAlgorithm' => 'rsassa-pss',
            'signatureAlgorithmParameters' => [
                'hashAlgorithm' => $hash->name(true),
                'maskGenAlgorithm' => [
                    'algorithm' => 'id-mgf1',
                    'parameters' => ['hashAlgorithm' => ($this->maskHashOverride ?? $hash)->name(true)],
                ],
                'saltLength' => $this->saltLengthOverride ?? $hash->digestLength(),
                'trailerField' => $this->trailerFieldOverride ?? '0xbc',
            ],
        ];
    }

    private function sign(string $data, HashAlgorithm $hash): string
    {
        $algorithm = SignatureAlgorithm::from(($this->legacyRsa ? 'RS' : 'PS') . ($hash->digestLength() * 8));
        $signature = $this->signer->privateKey->sign($algorithm, $data);
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
