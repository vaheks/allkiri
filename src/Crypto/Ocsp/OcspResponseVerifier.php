<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Ocsp;

use Allkiri\Crypto\Asn1\Oids;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\PublicKeyVerifier;
use Allkiri\Crypto\UnsupportedAlgorithmException;

/**
 * RFC 6960 response acceptance, without deciding trust in the CA itself
 * (that is the Trust layer's job before this is called).
 */
final class OcspResponseVerifier
{
    public function __construct(private readonly PublicKeyVerifier $verifier = new PublicKeyVerifier()) {}

    /**
     * @param string|null        $expectedNonce  the nonce sent with the request, if any
     * @param \DateTimeImmutable $validationTime "now" when signing; the timestamp's time when validating a stored response
     *
     * @throws OcspVerificationException when the response must not be relied on
     */
    public function verify(
        OcspResponse $response,
        Certificate $subject,
        Certificate $issuer,
        ?string $expectedNonce,
        \DateTimeImmutable $validationTime,
        OcspVerificationOptions $options,
    ): OcspVerificationResult {
        if ($response->status() !== OcspResponseStatus::Successful) {
            throw new OcspVerificationException(OcspVerificationException::REASON_STATUS, \sprintf('OCSP responder answered "%s"', $response->status()->value));
        }
        $basic = $response->basic() ?? throw new OcspVerificationException(OcspVerificationException::REASON_NOT_BASIC, 'OCSP response is not a BasicOCSPResponse');

        $single = $this->matchingResponse($basic, $subject, $issuer);
        $warnings = [];

        // Responder: the CA itself, a trusted-list anchor, or a delegated responder issued by the CA.
        $candidates = array_merge($basic->certificates(), $options->trustedResponders, [$issuer]);
        $responder = $basic->findResponder($candidates)
            ?? throw new OcspVerificationException(OcspVerificationException::REASON_RESPONDER_NOT_FOUND, 'OCSP responder certificate not found');

        try {
            $signatureOk = $this->verifier->verifyWithOid($responder->publicKey(), $basic->signatureAlgorithmOid(), $basic->tbsResponseDataDer(), $basic->signature());
        } catch (UnsupportedAlgorithmException $e) {
            throw new OcspVerificationException(OcspVerificationException::REASON_UNSUPPORTED_ALGORITHM, $e->getMessage(), $e);
        }
        if (!$signatureOk) {
            throw new OcspVerificationException(OcspVerificationException::REASON_BAD_SIGNATURE, 'OCSP response signature does not verify');
        }

        $responderIsIssuer = $responder->equals($issuer);
        $fromTrustList = false;
        foreach ($options->trustedResponders as $trusted) {
            if ($trusted->equals($responder)) {
                $fromTrustList = true;
            }
        }
        if (!$responderIsIssuer && !$fromTrustList) {
            if (!$responder->hasExtendedKeyUsage(Oids::ID_KP_OCSP_SIGNING)) {
                throw new OcspVerificationException(OcspVerificationException::REASON_RESPONDER_NOT_AUTHORISED, 'OCSP responder certificate lacks the OCSPSigning extended key usage');
            }
            if (!$responder->isSignedBy($issuer)) {
                throw new OcspVerificationException(OcspVerificationException::REASON_RESPONDER_NOT_AUTHORISED, 'OCSP responder certificate is not issued by the certificate\'s CA');
            }
        }
        if (!$responder->isValidAt($basic->producedAt())) {
            throw new OcspVerificationException(OcspVerificationException::REASON_RESPONDER_CERTIFICATE_INVALID, 'OCSP responder certificate was not valid when the response was produced');
        }

        $this->checkNonce($basic, $expectedNonce, $options->nonceMode);
        $this->checkTimes($basic, $single, $validationTime, $options, $warnings);

        return new OcspVerificationResult($response, $basic, $single, $responder, $responderIsIssuer, $fromTrustList, $warnings);
    }

    private function matchingResponse(BasicOcspResponse $basic, Certificate $subject, Certificate $issuer): SingleResponse
    {
        foreach ($basic->responses() as $single) {
            try {
                $expected = CertId::for($subject, $issuer, $single->certId->hashAlgorithmOid);
            } catch (UnsupportedAlgorithmException) {
                continue;
            }
            if ($expected->equals($single->certId)) {
                return $single;
            }
        }

        throw new OcspVerificationException(OcspVerificationException::REASON_NO_MATCHING_RESPONSE, 'OCSP response does not answer for this certificate');
    }

    private function checkNonce(BasicOcspResponse $basic, ?string $expected, NonceMode $mode): void
    {
        if ($mode === NonceMode::Ignore || $expected === null) {
            return;
        }
        $actual = $basic->nonce();
        if ($actual === null) {
            if ($mode === NonceMode::Required) {
                throw new OcspVerificationException(OcspVerificationException::REASON_NONCE_MISSING, 'OCSP response carries no nonce');
            }

            return;
        }
        if (!hash_equals($expected, $actual)) {
            throw new OcspVerificationException(OcspVerificationException::REASON_NONCE_MISMATCH, 'OCSP response nonce does not match the request');
        }
    }

    /**
     * @param list<string> $warnings
     */
    private function checkTimes(BasicOcspResponse $basic, SingleResponse $single, \DateTimeImmutable $at, OcspVerificationOptions $options, array &$warnings): void
    {
        $skew = $options->clockSkewSeconds;
        $time = $at->getTimestamp();
        $produced = $basic->producedAt()->getTimestamp();
        $thisUpdate = $single->thisUpdate->getTimestamp();

        if ($produced > $time + $skew) {
            throw new OcspVerificationException(OcspVerificationException::REASON_TIME, 'OCSP response was produced in the future');
        }
        if ($thisUpdate > $time + $skew) {
            throw new OcspVerificationException(OcspVerificationException::REASON_TIME, 'OCSP thisUpdate is in the future');
        }
        if ($options->maxAgeSeconds !== null && $produced < $time - $options->maxAgeSeconds) {
            throw new OcspVerificationException(OcspVerificationException::REASON_TIME, 'OCSP response is too old');
        }
        if ($single->nextUpdate !== null && $single->nextUpdate->getTimestamp() < $time - $skew) {
            if ($options->maxAgeSeconds !== null) {
                throw new OcspVerificationException(OcspVerificationException::REASON_TIME, 'OCSP response has expired (nextUpdate passed)');
            }
            $warnings[] = 'OCSP nextUpdate lies before the validation time';
        }
    }
}
