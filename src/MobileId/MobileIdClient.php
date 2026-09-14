<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\CertificateException;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Http\CurlHttpClient;
use Allkiri\Http\HttpClient;
use Allkiri\Http\HttpRequest;
use Allkiri\Http\HttpResponse;
use Allkiri\Http\TransportException;
use Psr\Log\LoggerInterface;

/**
 * The Mobile-ID REST API, one method per endpoint.
 *
 * This is the thin layer: it speaks JSON, maps failures onto typed exceptions
 * and does nothing else. The flows that a person actually goes through live in
 * {@see MobileIdAuthenticator} and {@see MobileIdSigner}.
 */
final class MobileIdClient
{
    public function __construct(
        private readonly MobileIdConfiguration $configuration,
        private readonly HttpClient $httpClient = new CurlHttpClient(),
        private readonly ?LoggerInterface $logger = null,
    ) {}

    public function configuration(): MobileIdConfiguration
    {
        return $this->configuration;
    }

    /**
     * The person's signing certificate, needed before a digest can be built.
     *
     * The phone is not involved, so this returns immediately.
     *
     * @throws CertificateNotFoundException when there is no active Mobile-ID
     * @throws MobileIdApiException
     */
    public function certificate(MobileIdIdentity $identity): Certificate
    {
        $body = $this->post('/certificate', [
            'phoneNumber' => $identity->phoneNumber,
            'nationalIdentityNumber' => $identity->nationalIdentityNumber,
        ]);

        $result = $this->stringField($body, 'result');
        if ($result !== 'OK') {
            // NOT_FOUND is the documented answer; anything else is still "no
            // certificate", and the reason belongs in the message. The person
            // does not: whether someone has Mobile-ID is personal data.
            $this->logger?->info('Mobile-ID has no certificate: {result}', ['result' => $result]);

            throw new CertificateNotFoundException($identity, $result);
        }

        return $this->certificateFrom($body, 'cert');
    }

    /**
     * Ask the person to authenticate. Returns the session identifier.
     *
     * @param string $hash the digest the phone will sign
     */
    public function startAuthentication(MobileIdIdentity $identity, string $hash, HashAlgorithm $hashAlgorithm): string
    {
        return $this->startSession(MobileIdSession::TYPE_AUTHENTICATION, $identity, $hash, $hashAlgorithm);
    }

    /**
     * Ask the person to sign. Returns the session identifier.
     */
    public function startSignature(MobileIdIdentity $identity, string $hash, HashAlgorithm $hashAlgorithm): string
    {
        return $this->startSession(MobileIdSession::TYPE_SIGNATURE, $identity, $hash, $hashAlgorithm);
    }

    /**
     * Ask once whether the session is finished, waiting up to the configured
     * poll timeout for the answer.
     *
     * The service holds the request open until something happens, so this is a
     * long poll rather than a busy loop: calling it repeatedly is correct.
     *
     * @param string $type one of the MobileIdSession::TYPE_ constants
     */
    public function status(string $type, string $sessionId, ?int $timeoutMs = null): MobileIdSessionStatus
    {
        $url = \sprintf(
            '%s/%s/session/%s?timeoutMs=%d',
            rtrim($this->configuration->url, '/'),
            rawurlencode($type),
            rawurlencode($sessionId),
            $timeoutMs ?? $this->configuration->pollTimeoutMs,
        );

        $body = $this->decode($this->send(HttpRequest::get($url, ['Accept' => 'application/json'])), $url);

        $state = $this->stringField($body, 'state');
        if ($state !== MobileIdSessionStatus::STATE_COMPLETE) {
            return new MobileIdSessionStatus(MobileIdSessionStatus::STATE_RUNNING);
        }

        $rawResult = $this->stringField($body, 'result');
        $result = MobileIdResult::tryFrom($rawResult);
        if ($result === null) {
            throw new MobileIdApiException(
                MobileIdApiException::REASON_MALFORMED_RESPONSE,
                \sprintf('Mobile-ID reported an unknown result "%s"', $rawResult),
            );
        }
        if ($result !== MobileIdResult::Ok) {
            return new MobileIdSessionStatus(MobileIdSessionStatus::STATE_COMPLETE, $result);
        }

        [$value, $algorithm] = $this->signatureFrom($body);

        return new MobileIdSessionStatus(
            MobileIdSessionStatus::STATE_COMPLETE,
            $result,
            $value,
            $algorithm,
            isset($body['cert']) ? $this->certificateFrom($body, 'cert') : null,
        );
    }

    private function startSession(string $type, MobileIdIdentity $identity, string $hash, HashAlgorithm $hashAlgorithm): string
    {
        $request = [
            'phoneNumber' => $identity->phoneNumber,
            'nationalIdentityNumber' => $identity->nationalIdentityNumber,
            'hash' => base64_encode($hash),
            'hashType' => $hashAlgorithm->name(),
            'language' => $this->configuration->language->value,
        ];
        if ($this->configuration->displayText !== '') {
            $request['displayText'] = $this->configuration->displayText;
            $request['displayTextFormat'] = $this->configuration->displayTextFormat->value;
        }

        $body = $this->post('/' . $type, $request);

        return $this->stringField($body, 'sessionID');
    }

    /**
     * @param array<string, mixed> $request
     *
     * @return array<string, mixed>
     */
    private function post(string $path, array $request): array
    {
        $url = rtrim($this->configuration->url, '/') . $path;
        $payload = json_encode([
            'relyingPartyUUID' => $this->configuration->relyingPartyUuid,
            'relyingPartyName' => $this->configuration->relyingPartyName,
        ] + $request, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);

        $response = $this->send(HttpRequest::post($url, 'application/json', $payload, ['Accept' => 'application/json']));

        return $this->decode($response, $url);
    }

    private function send(HttpRequest $request): HttpResponse
    {
        try {
            return $this->httpClient->send($request);
        } catch (TransportException $exception) {
            throw new MobileIdApiException(
                MobileIdApiException::REASON_TRANSPORT,
                \sprintf('Mobile-ID at %s could not be reached: %s', $request->redactedUrl(), $exception->getMessage()),
                null,
                $exception,
            );
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function decode(HttpResponse $response, string $url): array
    {
        if (!$response->isSuccess()) {
            throw MobileIdApiException::forStatus($response->status, $url, $response->body);
        }

        $decoded = json_decode($response->body, true);
        if (!\is_array($decoded)) {
            throw new MobileIdApiException(
                MobileIdApiException::REASON_MALFORMED_RESPONSE,
                \sprintf('Mobile-ID at %s answered with something that is not a JSON object', HttpRequest::withoutIdentities($url)),
                $response->status,
            );
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * @param array<string, mixed> $body
     */
    private function stringField(array $body, string $key): string
    {
        $value = $body[$key] ?? null;
        if (!\is_string($value) || $value === '') {
            throw new MobileIdApiException(
                MobileIdApiException::REASON_MALFORMED_RESPONSE,
                \sprintf('Mobile-ID answered without "%s"', $key),
            );
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $body
     */
    private function certificateFrom(array $body, string $key): Certificate
    {
        try {
            return Certificate::fromBase64($this->stringField($body, $key));
        } catch (CertificateException $exception) {
            throw new MobileIdApiException(
                MobileIdApiException::REASON_MALFORMED_RESPONSE,
                \sprintf('Mobile-ID answered with a certificate that cannot be read: %s', $exception->getMessage()),
                null,
                $exception,
            );
        }
    }

    /**
     * @param array<string, mixed> $body
     *
     * @return array{string, SignatureAlgorithm|null}
     */
    private function signatureFrom(array $body): array
    {
        $signature = $body['signature'] ?? null;
        if (!\is_array($signature)) {
            throw new MobileIdApiException(
                MobileIdApiException::REASON_MALFORMED_RESPONSE,
                'Mobile-ID reported OK but sent no signature',
            );
        }

        /** @var array<string, mixed> $signature */
        $value = base64_decode($this->stringField($signature, 'value'), true);
        if ($value === false || $value === '') {
            throw new MobileIdApiException(
                MobileIdApiException::REASON_MALFORMED_RESPONSE,
                'The Mobile-ID signature value is not base64',
            );
        }

        $algorithm = $signature['algorithm'] ?? null;

        return [$value, \is_string($algorithm) ? self::signatureAlgorithm($algorithm) : null];
    }

    /**
     * Mobile-ID names algorithms the JCA way: "SHA256WithECEncryption".
     *
     * Unknown names are not an error. The signature is verified against the
     * certificate we already hold, which settles the algorithm anyway.
     */
    public static function signatureAlgorithm(string $name): ?SignatureAlgorithm
    {
        if (preg_match('/^SHA(256|384|512)With(EC|RSA)/i', $name, $matches) !== 1) {
            return null;
        }

        return SignatureAlgorithm::tryFrom((strtoupper($matches[2]) === 'EC' ? 'ES' : 'RS') . $matches[1]);
    }
}
