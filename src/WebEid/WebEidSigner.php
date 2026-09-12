<?php

declare(strict_types=1);

namespace Allkiri\WebEid;

use Allkiri\Container\AsicContainer;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\CertificateException;
use Allkiri\Crypto\KeyType;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Signing\SigningOptions;
use Allkiri\Signing\SigningResult;
use Allkiri\Signing\SigningService;

/**
 * Signing a container with an ID card, through Web eID.
 *
 * The browser does three things and the server two, alternating:
 *
 * 1. the page calls `webeid.getSigningCertificate()` and posts the certificate
 *    and the algorithm list to the server;
 * 2. `prepare()` builds the XAdES against that certificate and returns the
 *    digest to sign;
 * 3. the page calls `webeid.sign(certificate, hash, hashFunction)`, which asks
 *    for PIN 2;
 * 4. the page posts the signature back;
 * 5. `complete()` puts it into the signature and finishes the container.
 *
 * The card decides its own padding — `sign()` is told only the hash function —
 * so the padding has to be worked out beforehand from what the card said it
 * supports. The XAdES declares its signature method at step 2, before the
 * signature exists, so what comes back at step 4 is checked against it and
 * refused if it differs.
 */
final class WebEidSigner
{
    public function __construct(
        private readonly SigningService $signingService,
    ) {}

    /**
     * Build the signature and return what the browser must sign.
     *
     * @param string       $certificateBase64 the `certificate` from `getSigningCertificate()`
     * @param list<mixed>  $supportedSignatureAlgorithms the list from the same call
     *
     * @throws WebEidException when the card supports nothing this library can put in a container
     */
    public function prepare(
        AsicContainer $container,
        string $certificateBase64,
        array $supportedSignatureAlgorithms,
        SigningOptions $options = new SigningOptions(),
    ): WebEidSigningSession {
        $certificate = $this->readCertificate($certificateBase64);
        $supported = CardAlgorithm::listFromArray($supportedSignatureAlgorithms);
        $chosen = $this->choose($certificate, $supported, $options->signatureAlgorithm);

        $signatureAlgorithm = $chosen->signatureAlgorithm();
        if ($signatureAlgorithm === null) {
            throw new WebEidException(\sprintf('The card algorithm %s has no XML-DSig signature method', $chosen));
        }

        $dataToBeSigned = $this->signingService->prepare($container, $certificate, $options->withAlgorithm($signatureAlgorithm));

        return new WebEidSigningSession($dataToBeSigned, $chosen);
    }

    /**
     * Put the value the card produced into the prepared signature.
     *
     * @param string            $signature the base64 `signature` from `sign()`
     * @param CardAlgorithm|null $reported the `signatureAlgorithm` from the same
     *                                     call; checked against what was prepared
     */
    public function complete(
        AsicContainer $container,
        WebEidSigningSession $session,
        string $signature,
        ?CardAlgorithm $reported = null,
    ): SigningResult {
        if ($reported !== null && !$reported->equals($session->algorithm)) {
            // The container already declares the method it was prepared with,
            // so a different one would make it describe itself wrongly.
            throw new WebEidException(\sprintf(
                'The card signed with %s but the signature was prepared for %s; the container would declare the wrong method',
                $reported,
                $session->algorithm,
            ));
        }

        $value = base64_decode($signature, true);
        if ($value === false || $value === '') {
            throw new WebEidException('The Web eID signature value is not base64');
        }

        // ECDSA values arrive as r‖s here, which is what XML-DSig wants, but
        // the signing service accepts either and checks the length.
        return $this->signingService->finalize($container, $session->dataToBeSigned, $value);
    }

    /**
     * Pick the algorithm to use.
     *
     * An explicit choice in the options is honoured, but only if the card
     * offers it: asking a card for something it cannot do fails later and less
     * clearly. Otherwise the strongest hash the card supports for its own key
     * type wins, which on an Estonian card means SHA-384 with its P-384 key.
     *
     * @param list<CardAlgorithm> $supported
     */
    private function choose(Certificate $certificate, array $supported, ?SignatureAlgorithm $requested): CardAlgorithm
    {
        if ($supported === []) {
            throw new WebEidException('The card reported no supported signature algorithms');
        }

        $keyType = $certificate->keyType();
        $usable = array_values(array_filter(
            $supported,
            static function (CardAlgorithm $algorithm) use ($keyType): bool {
                $signatureAlgorithm = $algorithm->signatureAlgorithm();

                return $signatureAlgorithm !== null && $signatureAlgorithm->keyType() === $keyType;
            },
        ));

        if ($usable === []) {
            throw new WebEidException(\sprintf(
                'The card supports none of the signature algorithms this library can put in a container; it offered %s',
                implode(', ', array_map(strval(...), $supported)),
            ));
        }

        if ($requested !== null) {
            foreach ($usable as $algorithm) {
                if ($algorithm->signatureAlgorithm() === $requested) {
                    return $algorithm;
                }
            }

            throw new WebEidException(\sprintf(
                '%s was requested but the card offers only %s',
                $requested->value,
                implode(', ', array_map(strval(...), $usable)),
            ));
        }

        usort($usable, static fn(CardAlgorithm $a, CardAlgorithm $b): int => self::rank($b) <=> self::rank($a));

        return $usable[0];
    }

    /**
     * Strongest hash first, and among equals prefer PSS over PKCS#1 v1.5.
     */
    private static function rank(CardAlgorithm $algorithm): int
    {
        $signatureAlgorithm = $algorithm->signatureAlgorithm();
        if ($signatureAlgorithm === null) {
            return 0;
        }

        return $signatureAlgorithm->hash()->digestLength() * 10
            + ($signatureAlgorithm->keyType() === KeyType::RSA && $signatureAlgorithm->isPss() ? 1 : 0);
    }

    private function readCertificate(string $base64): Certificate
    {
        try {
            return Certificate::fromBase64(trim($base64));
        } catch (CertificateException $exception) {
            throw new WebEidException('The signing certificate the browser sent could not be read: ' . $exception->getMessage(), 0, $exception);
        }
    }
}
