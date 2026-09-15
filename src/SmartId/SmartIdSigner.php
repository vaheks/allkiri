<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Container\AsicContainer;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Signing\SigningOptions;
use Allkiri\Signing\SigningResult;
use Allkiri\Signing\SigningService;

/**
 * Signing a container with Smart-ID.
 *
 * Smart-ID signs a bare digest and returns RSASSA-PSS, which is the only
 * algorithm SK still recommends. The XAdES signature therefore declares an
 * RFC 6931 PSS signature method, and the parameters the service reports are
 * checked to be the ones that method describes rather than assumed.
 *
 * The certificate has to be known before the digest exists, and Smart-ID will
 * only hand it over for a named account. So:
 *
 * - if you have the document number (from a previous sign-in), `start()` needs
 *   no interaction beyond the signature itself;
 * - if you only know the person, `chooseCertificate()` first asks their device
 *   which account to use, at the cost of one extra interaction.
 */
final class SmartIdSigner
{
    public function __construct(
        private readonly SmartIdClient $client,
        private readonly SigningService $signingService,
    ) {}

    /**
     * Ask the person's device which account should sign.
     *
     * Returns a session to poll; its result carries the document number that
     * `start()` then needs.
     */
    public function chooseCertificate(SemanticsIdentifier $identity, ?CertificateLevel $level = null): string
    {
        return $this->client->startNotificationCertificateChoice($identity, $level);
    }

    /**
     * The certificate an account will sign with. No interaction.
     */
    public function certificate(DocumentNumber $documentNumber, ?CertificateLevel $level = null): SmartIdCertificate
    {
        return $this->client->certificateByDocumentNumber($documentNumber, $level);
    }

    /**
     * Read a finished certificate-choice session.
     *
     * Such a session signs nothing, so it carries only the account the person
     * chose and its certificate. Store the document number: from then on no
     * further interaction is needed to prepare a signature.
     */
    public function completeCertificateChoice(SmartIdSessionStatus $status, ?CertificateLevel $level = null): SmartIdCertificate
    {
        $status->requireOk();

        $certificate = $status->certificate
            ?? throw new SmartIdApiException(SmartIdApiException::REASON_MALFORMED_RESPONSE, 'The certificate choice returned no certificate');
        $documentNumber = $status->documentNumber
            ?? throw new SmartIdApiException(SmartIdApiException::REASON_MALFORMED_RESPONSE, 'The certificate choice did not name the account that was chosen');

        $actual = $status->certificateLevel
            ?? throw new SmartIdApiException(SmartIdApiException::REASON_MALFORMED_RESPONSE, 'The certificate choice did not report a certificate level');
        $requested = $level ?? $this->client->configuration()->certificateLevel;
        if (!$requested->isSatisfiedBy($actual)) {
            throw new SmartIdException(\sprintf(
                'The chosen certificate is %s where %s was requested',
                $actual->value,
                $requested->value,
            ));
        }

        return new SmartIdCertificate($certificate, $actual, $documentNumber);
    }

    /**
     * Prepare the signature and push the request to the person's device.
     */
    public function startNotification(AsicContainer $container, DocumentNumber $documentNumber, Interactions $interactions, SigningOptions $options = new SigningOptions(), ?CertificateLevel $level = null): SmartIdSigningSession
    {
        $certificate = $this->certificate($documentNumber, $level);
        $dataToBeSigned = $this->signingService->prepare($container, $certificate->certificate, $this->options($options));

        $started = $this->client->startNotificationSignature(
            $documentNumber,
            $dataToBeSigned->digest,
            $dataToBeSigned->digestAlgorithm(),
            $interactions,
            $level,
        );

        return new SmartIdSigningSession(
            new SmartIdSession(
                $started['sessionId'],
                SmartIdSession::TYPE_SIGNATURE,
                $dataToBeSigned->digest,
                $interactions,
                $started['verificationCode'],
                $documentNumber->value,
                startedAt: $dataToBeSigned->createdAt,
            ),
            $dataToBeSigned,
        );
    }

    /**
     * Prepare the signature and return a session whose links send the person
     * into the app.
     */
    public function startDeviceLink(AsicContainer $container, DocumentNumber $documentNumber, Interactions $interactions, SigningOptions $options = new SigningOptions(), ?CertificateLevel $level = null, ?string $initialCallbackUrl = null): SmartIdSigningSession
    {
        SmartIdSession::requireUsableCallbackUrl($initialCallbackUrl);
        $interactions = $interactions->forDeviceLink();
        $certificate = $this->certificate($documentNumber, $level);
        $dataToBeSigned = $this->signingService->prepare($container, $certificate->certificate, $this->options($options));

        $response = $this->client->startDeviceLinkSignature(
            $documentNumber,
            $dataToBeSigned->digest,
            $dataToBeSigned->digestAlgorithm(),
            $interactions,
            $level,
            $initialCallbackUrl,
        );

        return new SmartIdSigningSession(
            new SmartIdSession(
                $response->sessionId,
                SmartIdSession::TYPE_SIGNATURE,
                $dataToBeSigned->digest,
                $interactions,
                VerificationCode::forData($dataToBeSigned->digest),
                $documentNumber->value,
                $response->sessionToken,
                $response->sessionSecret,
                $response->deviceLinkBase,
                $dataToBeSigned->createdAt,
                // Every link's authentication code covers it, so the links
                // built from a restored session need it too.
                $initialCallbackUrl,
            ),
            $dataToBeSigned,
        );
    }

    /**
     * Ask once whether the person has signed. Null means they have not yet.
     *
     * @throws SmartIdSessionException when they refused, or could not be reached
     */
    public function poll(AsicContainer $container, SmartIdSigningSession $signing): ?SigningResult
    {
        $status = $this->client->sessionStatus($signing->session->sessionId);
        if ($status->isRunning()) {
            return null;
        }

        return $this->complete($container, $signing, $status);
    }

    /**
     * Block until the person signs. Suitable for a console tool or a worker,
     * not for a web request.
     */
    public function sign(AsicContainer $container, SmartIdSigningSession $signing, ?SmartIdPoller $poller = null): SigningResult
    {
        return $this->complete($container, $signing, ($poller ?? new SmartIdPoller($this->client))->wait($signing->session));
    }

    /**
     * Put the value the app produced into the prepared signature.
     */
    public function complete(AsicContainer $container, SmartIdSigningSession $signing, SmartIdSessionStatus $status): SigningResult
    {
        $status->requireOk();

        if ($status->signatureProtocol !== SmartIdClient::PROTOCOL_RAW_DIGEST) {
            throw new SmartIdException(\sprintf(
                'Smart-ID answered with the %s protocol where this library expects %s',
                $status->signatureProtocol ?? 'unnamed',
                SmartIdClient::PROTOCOL_RAW_DIGEST,
            ));
        }

        $expected = $signing->dataToBeSigned->algorithm;
        $actual = $this->algorithmOf($status);
        if ($actual !== $expected) {
            // The XAdES already declares the method it was prepared with, so a
            // different one would make the signature undescribable rather than
            // merely surprising.
            throw new SmartIdException(\sprintf(
                'Smart-ID signed with %s but the signature was prepared as %s; the container would declare the wrong method',
                $actual->value,
                $expected->value,
            ));
        }

        $value = $status->signatureValue ?? '';
        if ($value === '') {
            throw new SmartIdApiException(SmartIdApiException::REASON_MALFORMED_RESPONSE, 'Smart-ID reported success with no signature value');
        }

        return $this->signingService->finalize($container, $signing->dataToBeSigned, $value);
    }

    /**
     * What the service actually used, as an XML-DSig signature method.
     */
    private function algorithmOf(SmartIdSessionStatus $status): SignatureAlgorithm
    {
        if ($status->pssParameters !== null) {
            $complaint = $status->pssParameters->complaint();
            if ($complaint !== null) {
                throw new SmartIdException('The Smart-ID signature uses PSS parameters no XML-DSig method describes: ' . $complaint);
            }

            return $status->pssParameters->signatureAlgorithm();
        }

        // Legacy PKCS#1 v1.5, which SK deprecates but still answers with when asked.
        return match ($status->signatureAlgorithmName) {
            'sha256WithRSAEncryption' => SignatureAlgorithm::RS256,
            'sha384WithRSAEncryption' => SignatureAlgorithm::RS384,
            'sha512WithRSAEncryption' => SignatureAlgorithm::RS512,
            default => throw new SmartIdException(\sprintf(
                'Smart-ID reported the signature algorithm "%s", which this library cannot put in a XAdES signature',
                $status->signatureAlgorithmName ?? 'none',
            )),
        };
    }

    /**
     * Smart-ID keys are RSA and SK deprecates PKCS#1 v1.5, so PSS is the
     * default here rather than whatever the key would otherwise suggest.
     */
    private function options(SigningOptions $options): SigningOptions
    {
        if ($options->signatureAlgorithm !== null) {
            return $options;
        }

        return $options->withAlgorithm(match ($this->client->configuration()->signingHashAlgorithm) {
            HashAlgorithm::SHA256 => SignatureAlgorithm::PS256,
            HashAlgorithm::SHA384 => SignatureAlgorithm::PS384,
            HashAlgorithm::SHA512 => SignatureAlgorithm::PS512,
        });
    }
}
