<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

use Allkiri\Container\AsicContainer;
use Allkiri\Signing\SigningOptions;
use Allkiri\Signing\SigningResult;
use Allkiri\Signing\SigningService;

/**
 * Signing a container with Mobile-ID.
 *
 * The same two halves as every remote signer: `start()` builds the XAdES
 * against the person's certificate and asks their phone for the signature
 * value; `complete()` puts the value back and finishes the signature to the
 * requested level.
 *
 * ```php
 * $session = $signer->start($container, $identity);
 * echo $session->verificationCode();           // show this to the person
 * // …store $session, poll from the browser…
 * $result = $signer->poll($container, $session);
 * ```
 */
final class MobileIdSigner
{
    public function __construct(
        private readonly MobileIdClient $client,
        private readonly SigningService $signingService,
    ) {}

    /**
     * Fetch the certificate, prepare the signature and ask the phone for it.
     *
     * @throws CertificateNotFoundException when the person has no active Mobile-ID
     */
    public function start(AsicContainer $container, MobileIdIdentity $identity, SigningOptions $options = new SigningOptions()): MobileIdSigningSession
    {
        $certificate = $this->client->certificate($identity);
        $dataToBeSigned = $this->signingService->prepare($container, $certificate, $options);

        $sessionId = $this->client->startSignature(
            $identity,
            $dataToBeSigned->digest,
            $dataToBeSigned->digestAlgorithm(),
        );

        return new MobileIdSigningSession(
            new MobileIdSession(
                $sessionId,
                MobileIdSession::TYPE_SIGNATURE,
                VerificationCode::forHash($dataToBeSigned->digest),
                $identity,
            ),
            $dataToBeSigned,
        );
    }

    /**
     * Ask once whether the person has signed. Null means they have not yet.
     *
     * @throws MobileIdSessionException when they cancelled, or could not be reached
     */
    public function poll(AsicContainer $container, MobileIdSigningSession $signing): ?SigningResult
    {
        $status = $this->client->status($signing->session->type, $signing->session->sessionId);
        if ($status->isRunning()) {
            return null;
        }

        return $this->complete($container, $signing, $status);
    }

    /**
     * Block until the person signs. Suitable for a console tool or a worker,
     * not for a web request.
     */
    public function sign(AsicContainer $container, MobileIdIdentity $identity, SigningOptions $options = new SigningOptions(), ?MobileIdPoller $poller = null): SigningResult
    {
        $signing = $this->start($container, $identity, $options);
        $status = ($poller ?? new MobileIdPoller($this->client))->wait($signing->session);

        return $this->complete($container, $signing, $status);
    }

    /**
     * Put the value the phone produced into the prepared signature.
     *
     * The value arrives as DER for ECDSA keys, which the signing service
     * converts to the r‖s form XML-DSig requires, and verifies against the
     * certificate before spending anything on a timestamp.
     */
    public function complete(AsicContainer $container, MobileIdSigningSession $signing, MobileIdSessionStatus $status): SigningResult
    {
        if (!$status->isOk()) {
            throw new MobileIdSessionException($status->result ?? MobileIdResult::Timeout);
        }

        return $this->signingService->finalize($container, $signing->dataToBeSigned, $status->requireSignature());
    }
}
