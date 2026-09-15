<?php

declare(strict_types=1);

namespace Allkiri\Crypto;

use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;

/**
 * The single place that configures phpseclib for signature verification, so
 * padding, MGF, salt length and ECDSA encoding are decided once.
 */
final class PublicKeyVerifier
{
    /**
     * Verify an XML-DSig / JWS style signature: RSA PKCS#1 or PSS bytes, or raw r‖s for ECDSA.
     */
    public function verify(PublicKey $key, SignatureAlgorithm $algorithm, string $data, string $signature): bool
    {
        if ($signature === '') {
            return false;
        }
        $hashName = $algorithm->hash()->value;

        try {
            if ($algorithm->keyType() === KeyType::RSA) {
                if (!$key instanceof RSA\PublicKey) {
                    return false;
                }

                return Phpseclib::bool($this->rsa($key, $hashName, $algorithm->isPss())->verify($data, $signature));
            }
            if (!$key instanceof EC\PublicKey) {
                return false;
            }
            if (\strlen($signature) !== 2 * EcdsaSignature::fieldBytes($key)) {
                return false;
            }

            return Phpseclib::bool($this->ec($key, $hashName, 'IEEE')->verify($data, $signature));
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Verify a signature described by an X.509 AlgorithmIdentifier OID, as
     * found in certificates, OCSP responses and CMS SignerInfos. ECDSA values
     * are DER here.
     *
     * @throws UnsupportedAlgorithmException for OIDs outside the table (including RSASSA-PSS, which needs parameters)
     */
    public function verifyWithOid(PublicKey $key, string $signatureAlgorithmOid, string $data, string $signature): bool
    {
        return $this->verifyWithAlgorithmIdentifier($key, SignatureAlgorithmIdentifier::fromOid($signatureAlgorithmOid), $data, $signature);
    }

    /**
     * Verify a signature under the algorithm its AlgorithmIdentifier names.
     *
     * This only says whether the signature is genuine. Whether its algorithm
     * and key are still acceptable is for {@see AlgorithmConstraints} to decide.
     */
    public function verifyWithAlgorithmIdentifier(PublicKey $key, SignatureAlgorithmIdentifier $algorithm, string $data, string $signature): bool
    {
        if ($signature === '') {
            return false;
        }

        try {
            if ($algorithm->keyType === KeyType::RSA) {
                return $key instanceof RSA\PublicKey && Phpseclib::bool($this->rsa($key, $algorithm->hashName, $algorithm->pss !== null, $algorithm->pss?->saltLength)->verify($data, $signature));
            }

            return $key instanceof EC\PublicKey && Phpseclib::bool($this->ec($key, $algorithm->hashName, 'ASN1')->verify($data, $signature));
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Whether {@see verifyWithOid()} can verify this algorithm. RSASSA-PSS is
     * not among them, because it cannot be verified from its OID alone; it is
     * verified through {@see verifyWithAlgorithmIdentifier()}.
     */
    public function supportsOid(string $signatureAlgorithmOid): bool
    {
        return SignatureAlgorithmIdentifier::isKnownOid($signatureAlgorithmOid);
    }

    /**
     * @param int|null $saltLength the declared PSS salt length; the digest length when null
     */
    private function rsa(RSA\PublicKey $key, string $hashName, bool $pss, ?int $saltLength = null): RSA\PublicKey
    {
        $key = Phpseclib::rsaPublic($key->withHash($hashName));
        if (!$pss) {
            return Phpseclib::rsaPublic($key->withPadding(RSA::SIGNATURE_PKCS1));
        }
        $saltLength ??= \strlen(hash($hashName, '', true));
        $key = Phpseclib::rsaPublic($key->withPadding(RSA::SIGNATURE_PSS));
        $key = Phpseclib::rsaPublic($key->withMGFHash($hashName));

        return Phpseclib::rsaPublic($key->withSaltLength($saltLength));
    }

    private function ec(EC\PublicKey $key, string $hashName, string $format): EC\PublicKey
    {
        $key = Phpseclib::ecPublic($key->withSignatureFormat($format));

        return Phpseclib::ecPublic($key->withHash($hashName));
    }
}
