<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\CertificateException;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Http\CurlHttpClient;
use Allkiri\Http\HttpClient;
use Allkiri\Http\HttpRequest;
use Allkiri\Http\HttpResponse;
use Allkiri\Http\TransportException;
use Psr\Log\LoggerInterface;

/**
 * The Smart-ID RP API v3, one method per endpoint.
 *
 * This is the thin layer: it speaks JSON, maps failures onto typed exceptions
 * and does nothing else. The flows a person goes through live in
 * {@see SmartIdAuthenticator} and {@see SmartIdSigner}.
 *
 * Two families of flow exist. **Notification** flows push a request to a
 * device the person has already registered, and the service returns the
 * verification code. **Device-link** flows return a link instead, which the
 * person follows from a QR code or a tap; the session only starts moving once
 * they do. Each family can address a person by semantics identifier or by
 * document number, and device-link authentication can address nobody at all,
 * letting whoever scans the code identify themselves.
 */
final class SmartIdClient
{
    public const PROTOCOL_ACSP_V2 = 'ACSP_V2';
    public const PROTOCOL_RAW_DIGEST = 'RAW_DIGEST_SIGNATURE';

    public const SIGNATURE_ALGORITHM_PSS = 'rsassa-pss';

    /** The only verification code shape the service offers, and the only one we show. */
    public const VERIFICATION_CODE_TYPE = 'numeric4';

    public function __construct(
        private readonly SmartIdConfiguration $configuration,
        private readonly HttpClient $httpClient = new CurlHttpClient(),
        private readonly ?LoggerInterface $logger = null,
    ) {}

    public function configuration(): SmartIdConfiguration
    {
        return $this->configuration;
    }

    // --- certificates -------------------------------------------------------

    /**
     * The signing certificate of one account, with no user interaction at all.
     *
     * This is the cheapest way to learn the certificate a digest must be built
     * against, and the reason an application should store the document number
     * when a person first signs in.
     */
    public function certificateByDocumentNumber(DocumentNumber $documentNumber, ?CertificateLevel $level = null): SmartIdCertificate
    {
        $body = $this->post('/signature/certificate/' . rawurlencode($documentNumber->value), $this->levelled([], $level));

        $state = $this->stringField($body, 'state');
        if ($state !== 'OK') {
            throw new SmartIdApiException(
                SmartIdApiException::REASON_ACCOUNT_NOT_FOUND,
                \sprintf('Smart-ID has no usable certificate for %s (state %s)', $documentNumber, $state),
            );
        }

        $cert = $body['cert'] ?? null;
        if (!\is_array($cert)) {
            throw new SmartIdApiException(SmartIdApiException::REASON_MALFORMED_RESPONSE, 'Smart-ID answered without a certificate');
        }

        /** @var array<string, mixed> $cert */
        return new SmartIdCertificate(
            $this->certificateFrom($cert, 'value'),
            $this->certificateLevelFrom($cert),
            $documentNumber,
        );
    }

    /**
     * Ask the person to choose a certificate, by push notification.
     *
     * Needed when only the person is known and not the account: it costs one
     * interaction but yields a document number, after which
     * {@see certificateByDocumentNumber()} needs none.
     *
     * @return string the session identifier
     */
    public function startNotificationCertificateChoice(SemanticsIdentifier $identity, ?CertificateLevel $level = null): string
    {
        $body = $this->post(
            '/signature/certificate-choice/notification/etsi/' . rawurlencode((string) $identity),
            $this->levelled([], $level),
        );

        return $this->stringField($body, 'sessionID');
    }

    // --- authentication -----------------------------------------------------

    /**
     * Start an authentication that any Smart-ID user can answer by scanning.
     *
     * Nobody is named in the request; who they are comes back in the
     * certificate. This is the flow behind a "log in with Smart-ID" QR code.
     */
    public function startAnonymousDeviceLinkAuthentication(string $rpChallenge, Interactions $interactions, ?CertificateLevel $level = null, ?string $initialCallbackUrl = null): DeviceLinkSessionResponse
    {
        return $this->deviceLinkSession(
            '/authentication/device-link/anonymous',
            $this->authenticationRequest($rpChallenge, $interactions, $level, $initialCallbackUrl),
        );
    }

    public function startDeviceLinkAuthentication(SemanticsIdentifier|DocumentNumber $subject, string $rpChallenge, Interactions $interactions, ?CertificateLevel $level = null, ?string $initialCallbackUrl = null): DeviceLinkSessionResponse
    {
        return $this->deviceLinkSession(
            $this->subjectPath('/authentication/device-link', $subject),
            $this->authenticationRequest($rpChallenge, $interactions, $level, $initialCallbackUrl),
        );
    }

    /**
     * Start an authentication as a push notification.
     *
     * Unlike a signature session, this returns only the session identifier.
     * The service does not hand back a verification code for an
     * authentication; the relying party derives it from the challenge it just
     * sent, and `vcType` tells the service which shape the app should show.
     *
     * @return string the session identifier
     */
    public function startNotificationAuthentication(SemanticsIdentifier|DocumentNumber $subject, string $rpChallenge, Interactions $interactions, ?CertificateLevel $level = null): string
    {
        $body = $this->post(
            $this->subjectPath('/authentication/notification', $subject),
            ['vcType' => self::VERIFICATION_CODE_TYPE] + $this->authenticationRequest($rpChallenge, $interactions, $level),
        );

        return $this->stringField($body, 'sessionID');
    }

    // --- signing ------------------------------------------------------------

    /**
     * Ask for a signature over a digest, as a push notification.
     *
     * @return array{sessionId: string, verificationCode: string}
     */
    public function startNotificationSignature(SemanticsIdentifier|DocumentNumber $subject, string $digest, HashAlgorithm $hashAlgorithm, Interactions $interactions, ?CertificateLevel $level = null): array
    {
        $body = $this->post(
            $this->subjectPath('/signature/notification', $subject),
            $this->signatureRequest($digest, $hashAlgorithm, $interactions, $level),
        );

        return [
            'sessionId' => $this->stringField($body, 'sessionID'),
            'verificationCode' => $this->verificationCodeFrom($body),
        ];
    }

    /**
     * Ask for a signature over a digest, through a device link.
     */
    public function startDeviceLinkSignature(SemanticsIdentifier|DocumentNumber $subject, string $digest, HashAlgorithm $hashAlgorithm, Interactions $interactions, ?CertificateLevel $level = null, ?string $initialCallbackUrl = null): DeviceLinkSessionResponse
    {
        return $this->deviceLinkSession(
            $this->subjectPath('/signature/device-link', $subject),
            $this->signatureRequest($digest, $hashAlgorithm, $interactions, $level, $initialCallbackUrl),
        );
    }

    // --- sessions -----------------------------------------------------------

    /**
     * Ask once whether the session is finished, waiting up to the configured
     * poll timeout for the answer.
     *
     * The service holds the request open until something happens, so calling
     * this repeatedly is correct rather than wasteful.
     */
    public function sessionStatus(string $sessionId, ?int $timeoutMs = null): SmartIdSessionStatus
    {
        $url = \sprintf(
            '%s/session/%s?timeoutMs=%d',
            rtrim($this->configuration->url, '/'),
            rawurlencode($sessionId),
            $timeoutMs ?? $this->configuration->pollTimeoutMs,
        );

        $body = $this->decode($this->send(HttpRequest::get($url, ['Accept' => 'application/json'])), $url, true);

        return SmartIdSessionStatusParser::parse($body);
    }

    // --- request bodies -----------------------------------------------------

    /**
     * @return array<string, mixed>
     */
    private function authenticationRequest(string $rpChallenge, Interactions $interactions, ?CertificateLevel $level, ?string $initialCallbackUrl = null): array
    {
        $request = [
            'signatureProtocol' => self::PROTOCOL_ACSP_V2,
            'signatureProtocolParameters' => [
                'rpChallenge' => base64_encode($rpChallenge),
                'signatureAlgorithm' => self::SIGNATURE_ALGORITHM_PSS,
                'signatureAlgorithmParameters' => ['hashAlgorithm' => self::hashName($this->configuration->signingHashAlgorithm)],
            ],
            'interactions' => $interactions->encoded,
        ];
        if ($initialCallbackUrl !== null) {
            $request['initialCallbackUrl'] = $initialCallbackUrl;
        }

        return $this->levelled($request, $level);
    }

    /**
     * @return array<string, mixed>
     */
    private function signatureRequest(string $digest, HashAlgorithm $hashAlgorithm, Interactions $interactions, ?CertificateLevel $level, ?string $initialCallbackUrl = null): array
    {
        $request = [
            'signatureProtocol' => self::PROTOCOL_RAW_DIGEST,
            'signatureProtocolParameters' => [
                'digest' => base64_encode($digest),
                'signatureAlgorithm' => self::SIGNATURE_ALGORITHM_PSS,
                'signatureAlgorithmParameters' => ['hashAlgorithm' => self::hashName($hashAlgorithm)],
            ],
            'interactions' => $interactions->encoded,
        ];
        if ($initialCallbackUrl !== null) {
            $request['initialCallbackUrl'] = $initialCallbackUrl;
        }

        return $this->levelled($request, $level);
    }

    /**
     * @param array<string, mixed> $request
     *
     * @return array<string, mixed>
     */
    private function levelled(array $request, ?CertificateLevel $level): array
    {
        $request['certificateLevel'] = ($level ?? $this->configuration->certificateLevel)->value;
        if ($this->configuration->shareDeviceIpAddress) {
            $request['requestProperties'] = ['shareMdClientIpAddress' => true];
        }

        return $request;
    }

    private function subjectPath(string $prefix, SemanticsIdentifier|DocumentNumber $subject): string
    {
        return $subject instanceof DocumentNumber
            ? $prefix . '/document/' . rawurlencode($subject->value)
            : $prefix . '/etsi/' . rawurlencode((string) $subject);
    }

    /**
     * Smart-ID spells hash algorithms with a hyphen: "SHA-256".
     */
    public static function hashName(HashAlgorithm $algorithm): string
    {
        return $algorithm->name(true);
    }

    // --- transport ----------------------------------------------------------

    /**
     * @param array<string, mixed> $request
     */
    private function deviceLinkSession(string $path, array $request): DeviceLinkSessionResponse
    {
        return DeviceLinkSessionResponse::fromArray($this->post($path, $request));
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

        $this->logger?->debug('Smart-ID POST {url}', ['url' => $url]);

        return $this->decode($this->send(HttpRequest::post($url, 'application/json', $payload, ['Accept' => 'application/json'])), $url);
    }

    private function send(HttpRequest $request): HttpResponse
    {
        try {
            return $this->httpClient->send($request);
        } catch (TransportException $exception) {
            throw new SmartIdApiException(
                SmartIdApiException::REASON_TRANSPORT,
                \sprintf('Smart-ID at %s could not be reached: %s', $request->url, $exception->getMessage()),
                null,
                $exception,
            );
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function decode(HttpResponse $response, string $url, bool $isSessionRequest = false): array
    {
        if (!$response->isSuccess()) {
            throw SmartIdApiException::forStatus($response->status, $url, $response->body, $isSessionRequest);
        }

        $decoded = json_decode($response->body, true);
        if (!\is_array($decoded)) {
            throw new SmartIdApiException(
                SmartIdApiException::REASON_MALFORMED_RESPONSE,
                \sprintf('Smart-ID at %s answered with something that is not a JSON object', $url),
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
            throw new SmartIdApiException(
                SmartIdApiException::REASON_MALFORMED_RESPONSE,
                \sprintf('Smart-ID answered without "%s"', $key),
            );
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $body
     */
    private function verificationCodeFrom(array $body): string
    {
        $vc = $body['vc'] ?? null;
        if (!\is_array($vc) || !\is_string($vc['value'] ?? null) || $vc['value'] === '') {
            throw new SmartIdApiException(
                SmartIdApiException::REASON_MALFORMED_RESPONSE,
                'Smart-ID started a notification session without a verification code to show',
            );
        }
        // A code of some other shape must not be shown as though it were four
        // digits: the person compares it character by character.
        $type = $vc['type'] ?? null;
        if (\is_string($type) && $type !== self::VERIFICATION_CODE_TYPE) {
            throw new SmartIdApiException(
                SmartIdApiException::REASON_MALFORMED_RESPONSE,
                \sprintf('Smart-ID returned a "%s" verification code, and this library only knows how to present "%s"', $type, self::VERIFICATION_CODE_TYPE),
            );
        }

        return $vc['value'];
    }

    /**
     * @param array<string, mixed> $body
     */
    private function certificateFrom(array $body, string $key): Certificate
    {
        try {
            return Certificate::fromBase64($this->stringField($body, $key));
        } catch (CertificateException $exception) {
            throw new SmartIdApiException(
                SmartIdApiException::REASON_MALFORMED_RESPONSE,
                \sprintf('Smart-ID answered with a certificate that cannot be read: %s', $exception->getMessage()),
                null,
                $exception,
            );
        }
    }

    /**
     * @param array<string, mixed> $body
     */
    private function certificateLevelFrom(array $body): CertificateLevel
    {
        $level = CertificateLevel::tryFrom($this->stringField($body, 'certificateLevel'));

        return $level ?? throw new SmartIdApiException(
            SmartIdApiException::REASON_MALFORMED_RESPONSE,
            \sprintf('Smart-ID reported an unknown certificate level "%s"', $this->stringField($body, 'certificateLevel')),
        );
    }
}
