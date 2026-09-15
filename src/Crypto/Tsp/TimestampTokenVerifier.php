<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Tsp;

use Allkiri\Crypto\AlgorithmConstraints;
use Allkiri\Crypto\Asn1\Oids;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\PublicKeyVerifier;
use Allkiri\Crypto\UnsupportedAlgorithmException;
use phpseclib3\Math\BigInteger;

/**
 * RFC 3161 §2.4.2 / RFC 5652 §5.6 token verification.
 */
final class TimestampTokenVerifier
{
    public function __construct(private readonly PublicKeyVerifier $verifier = new PublicKeyVerifier()) {}

    /**
     * @param string               $expectedImprint the digest the token must cover
     * @param list<Certificate>    $tsaCandidates   certificates to identify the TSU with when the token carries none
     * @param AlgorithmConstraints $constraints     what the token's signature must meet
     *
     * @throws TimestampVerificationException
     */
    public function verify(TimestampToken $token, HashAlgorithm $imprintAlgorithm, string $expectedImprint, ?BigInteger $expectedNonce = null, array $tsaCandidates = [], AlgorithmConstraints $constraints = new AlgorithmConstraints()): TimestampVerificationResult
    {
        $signedData = $token->signedData();
        $signerInfo = $token->signerInfo();
        $tstInfo = $token->tstInfo();

        $signedAttrs = $signerInfo->signedAttrsDer() ?? throw new TimestampVerificationException(TimestampVerificationException::REASON_STRUCTURE, 'Token signer has no signed attributes');
        if ($signerInfo->contentTypeAttribute() !== Oids::ID_CT_TST_INFO) {
            throw new TimestampVerificationException(TimestampVerificationException::REASON_CONTENT_TYPE, 'Token content-type attribute is not TSTInfo');
        }

        $eContent = $signedData->eContent() ?? '';
        $digestAlgorithm = HashAlgorithm::tryFromOid($signerInfo->digestAlgorithmOid())
            ?? throw new TimestampVerificationException(TimestampVerificationException::REASON_UNSUPPORTED_ALGORITHM, \sprintf('Unsupported token digest algorithm %s', $signerInfo->digestAlgorithmOid()));
        $messageDigest = $signerInfo->messageDigestAttribute()
            ?? throw new TimestampVerificationException(TimestampVerificationException::REASON_STRUCTURE, 'Token has no message-digest attribute');
        if (!hash_equals($digestAlgorithm->digest($eContent), $messageDigest)) {
            throw new TimestampVerificationException(TimestampVerificationException::REASON_MESSAGE_DIGEST, 'Token message-digest does not match the TSTInfo');
        }

        $tsa = $token->signerCertificate($tsaCandidates)
            ?? throw new TimestampVerificationException(TimestampVerificationException::REASON_SIGNER_NOT_FOUND, 'TSA certificate not found in the token');

        try {
            $algorithm = $signerInfo->signatureAlgorithm();
            $ok = $this->verifier->verifyWithAlgorithmIdentifier($tsa->publicKey(), $algorithm, $signedAttrs, $signerInfo->signature());
        } catch (UnsupportedAlgorithmException $e) {
            throw new TimestampVerificationException(TimestampVerificationException::REASON_UNSUPPORTED_ALGORITHM, $e->getMessage(), $e);
        }
        if (!$ok) {
            throw new TimestampVerificationException(TimestampVerificationException::REASON_BAD_SIGNATURE, 'Token signature does not verify');
        }
        // Reported only once everything else holds, so a weak algorithm names a
        // token that is otherwise sound.
        $weakness = $constraints->violation($algorithm, $tsa->publicKey());

        $references = $signerInfo->signingCertificateReferences();
        if ($references === []) {
            throw new TimestampVerificationException(TimestampVerificationException::REASON_ESS_MISMATCH, 'Token has no signing-certificate attribute');
        }
        $matched = false;
        foreach ($references as $reference) {
            if ($reference->matches($tsa)) {
                $matched = true;
                break;
            }
        }
        if (!$matched) {
            throw new TimestampVerificationException(TimestampVerificationException::REASON_ESS_MISMATCH, 'Token signing-certificate reference does not match the TSA certificate');
        }

        if (!$tsa->hasExtendedKeyUsage(Oids::ID_KP_TIMESTAMPING)) {
            throw new TimestampVerificationException(TimestampVerificationException::REASON_TSA_KEY_USAGE, 'TSA certificate lacks the timeStamping extended key usage');
        }

        if ($tstInfo->hashAlgorithmOid !== $imprintAlgorithm->oid() || !hash_equals($expectedImprint, $tstInfo->messageImprint)) {
            throw new TimestampVerificationException(TimestampVerificationException::REASON_IMPRINT, 'Token does not cover the expected message imprint');
        }
        if ($expectedNonce !== null && ($tstInfo->nonce === null || !$tstInfo->nonce->equals($expectedNonce))) {
            throw new TimestampVerificationException(TimestampVerificationException::REASON_NONCE, 'Token nonce does not match the request');
        }
        if ($weakness !== null) {
            throw new TimestampVerificationException(TimestampVerificationException::REASON_ALGORITHM_NOT_ACCEPTED, 'Token is ' . $weakness);
        }

        return new TimestampVerificationResult($token, $tsa);
    }
}
