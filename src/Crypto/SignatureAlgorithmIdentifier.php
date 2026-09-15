<?php

declare(strict_types=1);

namespace Allkiri\Crypto;

use Allkiri\Crypto\Asn1\Asn1;
use Allkiri\Crypto\Asn1\Asn1Exception;
use Allkiri\Crypto\Asn1\Oids;

/**
 * The algorithm a certificate, an OCSP response or a CMS signer names for its
 * signature, as read from its AlgorithmIdentifier.
 *
 * Being able to verify an algorithm and being willing to accept it are separate
 * questions. SHA-1 can still be verified here, so that a signature made with it
 * is reported as weak rather than as forged; {@see AlgorithmConstraints} decides
 * whether a signature that verifies still counts.
 */
final readonly class SignatureAlgorithmIdentifier
{
    /** Signature algorithm OID => [key type, PHP hash name] */
    private const TABLE = [
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
     * @param string $hashName the PHP hash name: sha1, sha256, sha384 or sha512
     */
    private function __construct(
        public string $oid,
        public KeyType $keyType,
        public string $hashName,
    ) {}

    /**
     * @throws UnsupportedAlgorithmException for an OID allkiri does not verify
     */
    public static function fromOid(string $oid): self
    {
        if ($oid === Oids::RSASSA_PSS) {
            throw new UnsupportedAlgorithmException('RSASSA-PSS cannot be verified from its OID alone; it needs the parameters of its AlgorithmIdentifier');
        }
        [$keyType, $hashName] = self::TABLE[$oid] ?? throw new UnsupportedAlgorithmException(\sprintf('Unsupported signature algorithm OID "%s"', $oid));

        return new self($oid, $keyType, $hashName);
    }

    /**
     * @param string $der a whole AlgorithmIdentifier: SEQUENCE { algorithm, parameters OPTIONAL }
     *
     * @throws UnsupportedAlgorithmException for an OID allkiri does not verify, or DER that is not an AlgorithmIdentifier
     */
    public static function fromDer(string $der): self
    {
        try {
            $node = Asn1::decodeRaw($der);
            if (!$node->isSequence() || $node->childCount() < 1 || $node->childCount() > 2) {
                throw new Asn1Exception('not a SEQUENCE of an OID and optional parameters');
            }
            $oid = $node->child(0)->oid();
        } catch (Asn1Exception $e) {
            throw new UnsupportedAlgorithmException('Malformed signature AlgorithmIdentifier: ' . $e->getMessage(), 0, $e);
        }

        return self::fromOid($oid);
    }

    public static function isKnownOid(string $oid): bool
    {
        return isset(self::TABLE[$oid]);
    }

    /**
     * The digest, or null for SHA-1, which allkiri verifies but no longer accepts.
     */
    public function hash(): ?HashAlgorithm
    {
        return HashAlgorithm::tryFrom($this->hashName);
    }
}
