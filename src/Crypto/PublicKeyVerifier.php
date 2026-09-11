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
    /** X.509 / CMS / OCSP signature algorithm OIDs allkiri can verify: OID => [key type, php hash name] */
    private const OID_TABLE = [
        '1.2.840.113549.1.1.5' => [KeyType::RSA, 'sha1'],
        '1.2.840.113549.1.1.11' => [KeyType::RSA, 'sha256'],
        '1.2.840.113549.1.1.12' => [KeyType::RSA, 'sha384'],
        '1.2.840.113549.1.1.13' => [KeyType::RSA, 'sha512'],
        '1.2.840.10045.4.1' => [KeyType::EC, 'sha1'],
        '1.2.840.10045.4.3.2' => [KeyType::EC, 'sha256'],
        '1.2.840.10045.4.3.3' => [KeyType::EC, 'sha384'],
        '1.2.840.10045.4.3.4' => [KeyType::EC, 'sha512'],
    ];

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
        $entry = self::OID_TABLE[$signatureAlgorithmOid] ?? throw new UnsupportedAlgorithmException(\sprintf('Unsupported signature algorithm OID "%s"', $signatureAlgorithmOid));
        [$keyType, $hashName] = $entry;
        if ($signature === '') {
            return false;
        }

        try {
            if ($keyType === KeyType::RSA) {
                return $key instanceof RSA\PublicKey && Phpseclib::bool($this->rsa($key, $hashName, false)->verify($data, $signature));
            }

            return $key instanceof EC\PublicKey && Phpseclib::bool($this->ec($key, $hashName, 'ASN1')->verify($data, $signature));
        } catch (\Throwable) {
            return false;
        }
    }

    public function supportsOid(string $signatureAlgorithmOid): bool
    {
        return isset(self::OID_TABLE[$signatureAlgorithmOid]);
    }

    private function rsa(RSA\PublicKey $key, string $hashName, bool $pss): RSA\PublicKey
    {
        $key = Phpseclib::rsaPublic($key->withHash($hashName));
        if (!$pss) {
            return Phpseclib::rsaPublic($key->withPadding(RSA::SIGNATURE_PKCS1));
        }
        $saltLength = \strlen(hash($hashName, '', true));
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
