<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Auth\AuthenticatedIdentity;
use Allkiri\Clock\SystemClock;
use Allkiri\Crypto\NonceGenerator;
use Allkiri\Crypto\PublicKeyVerifier;
use Allkiri\Crypto\RandomNonceGenerator;
use Allkiri\Trust\ChainBuilder;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustException;
use Psr\Clock\ClockInterface;

/**
 * Signing in with Smart-ID.
 *
 * Two families of flow, both in two steps:
 *
 * - **Notification**: the service pushes the request to a device the person has
 *   registered and returns a verification code to show them.
 * - **Device link**: the service returns a link instead, which the person
 *   follows from a QR code or a tap. `startAnonymous()` names nobody, so
 *   whoever scans identifies themselves.
 *
 * Nothing about the person is believed until the returned signature verifies
 * over the exact payload this session implies.
 */
final class SmartIdAuthenticator
{
    /** SK's own client uses 64 bytes and requires at least 32. */
    private const CHALLENGE_BYTES = 64;

    public function __construct(
        private readonly SmartIdClient $client,
        private readonly ?ChainBuilder $chainBuilder = null,
        private readonly NonceGenerator $nonceGenerator = new RandomNonceGenerator(),
        private readonly ClockInterface $clock = new SystemClock(),
        private readonly PublicKeyVerifier $verifier = new PublicKeyVerifier(),
        private readonly ?string $brokeredRelyingPartyName = null,
    ) {}

    // --- starting -----------------------------------------------------------

    /**
     * Push an authentication request to the person's device.
     *
     * Show `$session->verificationCode` immediately: it is what lets them see
     * that the request on their phone is the one they started here.
     */
    public function startNotification(SemanticsIdentifier|DocumentNumber $subject, Interactions $interactions, ?CertificateLevel $level = null): SmartIdSession
    {
        $challenge = $this->nonceGenerator->generate(self::CHALLENGE_BYTES);
        $sessionId = $this->client->startNotificationAuthentication($subject, $challenge, $interactions, $level);

        return new SmartIdSession(
            $sessionId,
            SmartIdSession::TYPE_AUTHENTICATION,
            $challenge,
            $interactions,
            // An authentication's code is not handed back by the service; both
            // sides derive it from the challenge.
            VerificationCode::forData($challenge),
            $subject instanceof DocumentNumber ? $subject->value : null,
            startedAt: $this->now(),
        );
    }

    /**
     * Start an authentication anyone can answer by scanning.
     *
     * The person is not named; who they are comes back in the certificate.
     */
    public function startAnonymous(Interactions $interactions, ?CertificateLevel $level = null, ?string $initialCallbackUrl = null): SmartIdSession
    {
        $interactions = $interactions->forDeviceLink();
        $challenge = $this->nonceGenerator->generate(self::CHALLENGE_BYTES);
        $response = $this->client->startAnonymousDeviceLinkAuthentication($challenge, $interactions, $level, $initialCallbackUrl);

        return $this->deviceLinkSession($response, $challenge, $interactions, null);
    }

    /**
     * Start a device-link authentication for a person who is already known.
     */
    public function startDeviceLink(SemanticsIdentifier|DocumentNumber $subject, Interactions $interactions, ?CertificateLevel $level = null, ?string $initialCallbackUrl = null): SmartIdSession
    {
        $interactions = $interactions->forDeviceLink();
        $challenge = $this->nonceGenerator->generate(self::CHALLENGE_BYTES);
        $response = $this->client->startDeviceLinkAuthentication($subject, $challenge, $interactions, $level, $initialCallbackUrl);

        return $this->deviceLinkSession($response, $challenge, $interactions, $subject instanceof DocumentNumber ? $subject->value : null);
    }

    // --- finishing ----------------------------------------------------------

    /**
     * Ask once whether the person is done. Null means they are not yet.
     *
     * @param string|null $userChallengeVerifier the value a Web2App or App2App
     *                                          callback returned, when one was used
     *
     * @throws SmartIdSessionException when they refused, or could not be reached
     */
    public function poll(SmartIdSession $session, ?string $userChallengeVerifier = null): ?AuthenticatedIdentity
    {
        $status = $this->client->sessionStatus($session->sessionId);
        if ($status->isRunning()) {
            return null;
        }

        return $this->complete($session, $status, $userChallengeVerifier);
    }

    /**
     * Block until the person answers. Suitable for a console tool or a worker,
     * not for a web request.
     */
    public function authenticate(SmartIdSession $session, ?SmartIdPoller $poller = null): AuthenticatedIdentity
    {
        return $this->complete($session, ($poller ?? new SmartIdPoller($this->client))->wait($session));
    }

    /**
     * Check a finished session and return who it proves was there.
     */
    public function complete(SmartIdSession $session, SmartIdSessionStatus $status, ?string $userChallengeVerifier = null): AuthenticatedIdentity
    {
        if ($session->type !== SmartIdSession::TYPE_AUTHENTICATION) {
            throw new SmartIdException('This session is a signing session, not an authentication');
        }
        $status->requireOk();

        $configuration = $this->client->configuration();
        $certificate = $status->certificate
            ?? throw new SmartIdApiException(SmartIdApiException::REASON_MALFORMED_RESPONSE, 'Smart-ID authenticated without returning a certificate');

        if ($status->signatureProtocol !== AcspV2Payload::PROTOCOL) {
            throw new SmartIdException(\sprintf(
                'Smart-ID answered with the %s protocol where this library expects %s',
                $status->signatureProtocol ?? 'unnamed',
                AcspV2Payload::PROTOCOL,
            ));
        }
        // Every session reports which dialogue was shown, and it is part of
        // what was signed, so a missing one would make the payload guesswork.
        if ($status->interactionTypeUsed === null) {
            throw new SmartIdApiException(
                SmartIdApiException::REASON_MALFORMED_RESPONSE,
                'Smart-ID authenticated without saying which dialogue the app showed',
            );
        }

        // Authentication is PSS only. A PKCS#1 v1.5 answer would mean the
        // service changed under us, and the parameters below would not describe it.
        $pss = $status->pssParameters
            ?? throw new SmartIdException('Smart-ID authenticated with a signature algorithm this library does not accept for authentication');
        $complaint = $pss->complaint();
        if ($complaint !== null) {
            throw new SmartIdException('The Smart-ID signature uses parameters this library will not accept: ' . $complaint);
        }

        $this->verifyUserChallenge($status, $userChallengeVerifier);

        $payload = AcspV2Payload::forSession($configuration, $session, $status, $this->brokeredRelyingPartyName);
        $signature = $status->signatureValue ?? '';
        if ($signature === '' || !$this->verifier->verify($certificate->publicKey(), $pss->signatureAlgorithm(), $payload->bytes(), $signature)) {
            throw new SmartIdException('The Smart-ID signature does not match this session; it proves nothing');
        }

        $this->verifyCertificate($certificate, $status);

        return AuthenticatedIdentity::fromCertificate($certificate);
    }

    // --- checks -------------------------------------------------------------

    /**
     * A Web2App or App2App callback returns a verifier whose digest must equal
     * the user challenge the service reported. It is what ties the browser that
     * came back to the app that answered.
     */
    private function verifyUserChallenge(SmartIdSessionStatus $status, ?string $userChallengeVerifier): void
    {
        if ($userChallengeVerifier === null) {
            return;
        }
        if ($status->userChallenge === null) {
            throw new SmartIdException('A user challenge verifier was supplied but Smart-ID reported no user challenge');
        }
        $expected = DeviceLink::base64Url(hash('sha256', $userChallengeVerifier, true));
        if (!hash_equals($status->userChallenge, $expected)) {
            throw new SmartIdException('The user challenge verifier from the callback does not match the session');
        }
    }

    private function verifyCertificate(\Allkiri\Crypto\Certificate $certificate, SmartIdSessionStatus $status): void
    {
        $requested = $this->client->configuration()->certificateLevel;
        $actual = $status->certificateLevel;
        if ($actual !== null && !$requested->isSatisfiedBy($actual)) {
            throw new SmartIdException(\sprintf(
                'Smart-ID returned a %s certificate where %s was requested',
                $actual->value,
                $requested->value,
            ));
        }

        $now = $this->now();
        if (!$certificate->isValidAt($now)) {
            throw new SmartIdException('The Smart-ID certificate is not valid at this moment');
        }
        if ($this->chainBuilder !== null) {
            try {
                $this->chainBuilder->build($certificate, [], $now, [ServiceType::CaQc, ServiceType::CaPkc]);
            } catch (TrustException $exception) {
                throw new SmartIdException('The Smart-ID certificate does not chain to a trusted authority: ' . $exception->getMessage(), 0, $exception);
            }
        }
    }

    private function deviceLinkSession(DeviceLinkSessionResponse $response, string $challenge, Interactions $interactions, ?string $documentNumber): SmartIdSession
    {
        return new SmartIdSession(
            $response->sessionId,
            SmartIdSession::TYPE_AUTHENTICATION,
            $challenge,
            $interactions,
            // Nothing is pushed, so the code is derived from the challenge the
            // app will see rather than handed to us.
            VerificationCode::forData($challenge),
            $documentNumber,
            $response->sessionToken,
            $response->sessionSecret,
            $response->deviceLinkBase,
            $this->now(),
        );
    }

    private function now(): \DateTimeImmutable
    {
        return $this->clock->now()->setTimezone(new \DateTimeZone('UTC'));
    }
}
