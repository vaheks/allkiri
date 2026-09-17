<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Auth\AuthenticatedIdentity;
use Allkiri\Auth\UnidentifiableCertificateException;
use Allkiri\Clock\SystemClock;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\NonceGenerator;
use Allkiri\Crypto\Ocsp\CertificateRevokedException;
use Allkiri\Crypto\Ocsp\OcspClient;
use Allkiri\Crypto\Ocsp\OcspException;
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
 * over the exact payload this session implies, and the certificate chains to a
 * trusted authority and has not been revoked.
 */
final class SmartIdAuthenticator
{
    /** SK's own client uses 64 bytes and requires at least 32. */
    private const CHALLENGE_BYTES = 64;

    public function __construct(
        private readonly SmartIdClient $client,
        private readonly ChainBuilder $chainBuilder,
        private readonly OcspClient $ocspClient,
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
     *
     * @param CertificateLevel|null $level the level to require; the configuration's when null
     */
    public function startNotification(SemanticsIdentifier|DocumentNumber $subject, Interactions $interactions, ?CertificateLevel $level = null): SmartIdSession
    {
        $level ??= $this->client->configuration()->certificateLevel;
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
            certificateLevel: $level,
            semanticsIdentifier: $subject instanceof SemanticsIdentifier ? $subject : null,
        );
    }

    /**
     * Start an authentication anyone can answer by scanning.
     *
     * The person is not named; who they are comes back in the certificate.
     *
     * @param CertificateLevel|null $level              the level to require; the configuration's when null
     * @param string|null           $initialCallbackUrl where a Web2App or App2App flow sends the person back.
     *                                                  The session keeps it, because the app signs it.
     */
    public function startAnonymous(Interactions $interactions, ?CertificateLevel $level = null, ?string $initialCallbackUrl = null): SmartIdSession
    {
        SmartIdSession::requireUsableCallbackUrl($initialCallbackUrl);
        $level ??= $this->client->configuration()->certificateLevel;
        $interactions = $interactions->forDeviceLink();
        $challenge = $this->nonceGenerator->generate(self::CHALLENGE_BYTES);
        $response = $this->client->startAnonymousDeviceLinkAuthentication($challenge, $interactions, $level, $initialCallbackUrl);

        return $this->deviceLinkSession($response, $challenge, $interactions, null, $initialCallbackUrl, $level);
    }

    /**
     * Start a device-link authentication for a person who is already known.
     *
     * @param CertificateLevel|null $level              the level to require; the configuration's when null
     * @param string|null           $initialCallbackUrl where a Web2App or App2App flow sends the person back.
     *                                                  The session keeps it, because the app signs it.
     */
    public function startDeviceLink(SemanticsIdentifier|DocumentNumber $subject, Interactions $interactions, ?CertificateLevel $level = null, ?string $initialCallbackUrl = null): SmartIdSession
    {
        SmartIdSession::requireUsableCallbackUrl($initialCallbackUrl);
        $level ??= $this->client->configuration()->certificateLevel;
        $interactions = $interactions->forDeviceLink();
        $challenge = $this->nonceGenerator->generate(self::CHALLENGE_BYTES);
        $response = $this->client->startDeviceLinkAuthentication($subject, $challenge, $interactions, $level, $initialCallbackUrl);

        return $this->deviceLinkSession($response, $challenge, $interactions, $subject, $initialCallbackUrl, $level);
    }

    // --- finishing ----------------------------------------------------------

    /**
     * Ask once whether the person is done. Null means they are not yet.
     *
     * @param SmartIdCallback|null $callback what the app brought back to your callback URL;
     *                                       required for a Web2App or App2App answer
     *
     * @throws SmartIdSessionException when they refused, or could not be reached
     */
    public function poll(SmartIdSession $session, ?SmartIdCallback $callback = null): ?AuthenticatedIdentity
    {
        $status = $this->client->sessionStatus($session->sessionId);
        if ($status->isRunning()) {
            return null;
        }

        return $this->complete($session, $status, $callback);
    }

    /**
     * Block until the person answers. Suitable for a console tool or a worker,
     * not for a web request, and not for Web2App or App2App, whose answer
     * arrives through a callback.
     */
    public function authenticate(SmartIdSession $session, ?SmartIdPoller $poller = null): AuthenticatedIdentity
    {
        return $this->complete($session, ($poller ?? new SmartIdPoller($this->client))->wait($session));
    }

    /**
     * Check a finished session and return who it proves was there.
     *
     * @param SmartIdCallback|null $callback what the app brought back to your callback URL;
     *                                       required for a Web2App or App2App answer
     */
    public function complete(SmartIdSession $session, SmartIdSessionStatus $status, ?SmartIdCallback $callback = null): AuthenticatedIdentity
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

        $this->verifyCallback($session, $status, $callback);

        $payload = AcspV2Payload::forSession($configuration, $session, $status, $this->brokeredRelyingPartyName);
        $signature = $status->signatureValue ?? '';
        if ($signature === '' || !$this->verifier->verify($certificate->publicKey(), $pss->signatureAlgorithm(), $payload->bytes(), $signature)) {
            throw new SmartIdException('The Smart-ID signature does not match this session; it proves nothing');
        }

        $this->verifyCertificate($certificate, $session, $status);

        try {
            $identity = AuthenticatedIdentity::fromCertificate($certificate);
        } catch (UnidentifiableCertificateException $exception) {
            throw new SmartIdException('The Smart-ID certificate does not name a person: ' . $exception->getMessage(), 0, $exception);
        }
        $this->verifyAccount($session, $status, $identity);

        return $identity;
    }

    // --- checks -------------------------------------------------------------

    /**
     * A Web2App or App2App answer counts only together with the callback the
     * app opened. The callback shows that Smart-ID sent the person back for
     * this session, and its verifier, whose digest must equal the user
     * challenge the service reported, ties the browser that came back to the
     * app that answered. Without them, an answer shows only that somebody
     * approved the session, not that they are the person in this browser.
     */
    private function verifyCallback(SmartIdSession $session, SmartIdSessionStatus $status, ?SmartIdCallback $callback): void
    {
        if ($callback === null) {
            if ($status->flowType === FlowType::Web2App || $status->flowType === FlowType::App2App) {
                throw new SmartIdException(\sprintf(
                    'Smart-ID answered through %s, which needs the callback the app opened; pass it to poll()',
                    $status->flowType->value,
                ));
            }

            return;
        }
        $session->verifyCallback($callback);
        $userChallengeVerifier = $callback->userChallengeVerifier()
            ?? throw new SmartIdException('The callback carries no userChallengeVerifier, which an authentication needs');
        if ($status->userChallenge === null) {
            throw new SmartIdException('A user challenge verifier was supplied but Smart-ID reported no user challenge');
        }
        $expected = DeviceLink::base64Url(hash('sha256', $userChallengeVerifier, true));
        if (!hash_equals($status->userChallenge, $expected)) {
            throw new SmartIdException('The user challenge verifier from the callback does not match the session');
        }
    }

    private function verifyCertificate(Certificate $certificate, SmartIdSession $session, SmartIdSessionStatus $status): void
    {
        // A session stored before the level was kept is judged against the
        // configuration, as it would have been when it started.
        $configuration = $this->client->configuration();
        $requested = $session->certificateLevel ?? $configuration->certificateLevel;
        $actual = $status->certificateLevel
            ?? throw new SmartIdApiException(SmartIdApiException::REASON_MALFORMED_RESPONSE, 'Smart-ID authenticated without saying what level of certificate answered');
        if (!$requested->isSatisfiedBy($actual)) {
            throw new SmartIdException(\sprintf(
                'Smart-ID returned a %s certificate where %s was requested',
                $actual->value,
                $requested->value,
            ));
        }

        // The level is reported beside the signature, not inside what was
        // signed, so it is believed only as far as the certificate bears it out.
        $missing = array_values(array_diff($actual->authenticationPolicies(), $certificate->policies()));
        if ($missing !== []) {
            throw new SmartIdException(\sprintf(
                'Smart-ID reported a %s certificate, but the certificate lacks the policies of one: %s',
                $actual->value,
                implode(', ', $missing),
            ));
        }

        $now = $this->now();
        if (!$certificate->isValidAt($now)) {
            throw new SmartIdException('The Smart-ID certificate is not valid at this moment');
        }
        try {
            $chain = $this->chainBuilder->build($certificate, [], $now, [ServiceType::CaQc, ServiceType::CaPkc]);
        } catch (TrustException $exception) {
            throw new SmartIdException('The Smart-ID certificate does not chain to a trusted authority: ' . $exception->getMessage(), 0, $exception);
        }

        // SK's guidance for verifying an answer asks relying parties to check
        // that the certificate has not been revoked.
        if (!$configuration->checkRevocation) {
            return;
        }
        try {
            $this->ocspClient->fetch($certificate, $chain->issuerOfLeaf());
        } catch (CertificateRevokedException $exception) {
            // A revoked certificate, or one the responder has never heard of,
            // is a final answer about the certificate. A responder that could
            // not be reached is a problem of ours, and is reported as such.
            throw new SmartIdException(
                $exception->reason === CertificateRevokedException::REASON_REVOKED
                    ? 'The Smart-ID certificate has been revoked'
                    : 'The OCSP responder does not recognise the Smart-ID certificate',
                0,
                $exception,
            );
        } catch (OcspException $exception) {
            throw new SmartIdException('The Smart-ID certificate\'s revocation status could not be established: ' . $exception->getMessage(), 0, $exception);
        }
    }

    /**
     * The account that answered must be the one the session asked for, and the
     * certificate must belong to that account.
     *
     * The identity returned is read from the verified certificate either way.
     * This matters to an application that trusts its own input, for instance
     * one that shows "signed in as" the code the person typed.
     */
    private function verifyAccount(SmartIdSession $session, SmartIdSessionStatus $status, AuthenticatedIdentity $identity): void
    {
        $documentNumber = $status->documentNumber
            ?? throw new SmartIdApiException(SmartIdApiException::REASON_MALFORMED_RESPONSE, 'Smart-ID authenticated without naming the account that answered');
        if ($session->documentNumber !== null && $session->documentNumber !== $documentNumber->value) {
            throw new SmartIdException(\sprintf(
                'Smart-ID answered from account %s but the session was started for %s',
                $documentNumber->value,
                $session->documentNumber,
            ));
        }

        $account = (string) $documentNumber->semanticsIdentifier();
        if ($session->semanticsIdentifier !== null && (string) $session->semanticsIdentifier !== $account) {
            throw new SmartIdException(\sprintf(
                'Smart-ID answered for %s but the session was started for %s',
                $account,
                $session->semanticsIdentifier,
            ));
        }
        if ($identity->semanticsIdentifier() !== $account) {
            throw new SmartIdException(\sprintf(
                'The Smart-ID certificate belongs to %s but the account that answered belongs to %s',
                $identity->semanticsIdentifier(),
                $account,
            ));
        }
    }

    private function deviceLinkSession(
        DeviceLinkSessionResponse $response,
        string $challenge,
        Interactions $interactions,
        SemanticsIdentifier|DocumentNumber|null $subject,
        ?string $initialCallbackUrl,
        CertificateLevel $level,
    ): SmartIdSession {
        return new SmartIdSession(
            $response->sessionId,
            SmartIdSession::TYPE_AUTHENTICATION,
            $challenge,
            $interactions,
            // Nothing is pushed, so the code is derived from the challenge the
            // app will see rather than handed to us.
            VerificationCode::forData($challenge),
            $subject instanceof DocumentNumber ? $subject->value : null,
            $response->sessionToken,
            $response->sessionSecret,
            $response->deviceLinkBase,
            $this->now(),
            $initialCallbackUrl,
            $level,
            $subject instanceof SemanticsIdentifier ? $subject : null,
        );
    }

    private function now(): \DateTimeImmutable
    {
        return $this->clock->now()->setTimezone(new \DateTimeZone('UTC'));
    }
}
