<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Ocsp;

use Allkiri\Crypto\Asn1\Asn1Exception;
use Allkiri\Crypto\Asn1\Oids;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\UnsupportedAlgorithmException;
use phpseclib3\Math\BigInteger;

/**
 * OCSP CertID (RFC 6960 §4.1.1): which certificate a request or single
 * response is about.
 */
final readonly class CertId
{
    public function __construct(
        public string $hashAlgorithmOid,
        public string $issuerNameHash,
        public string $issuerKeyHash,
        public string $serialNumber,
    ) {}

    /**
     * @param string $hashAlgorithmOid SHA-1 is what responders in the wild (SK included) expect; SHA-256 works with SK too
     */
    public static function for(Certificate $subject, Certificate $issuer, string $hashAlgorithmOid = Oids::SHA1): self
    {
        $hash = self::phpHash($hashAlgorithmOid);

        return new self(
            $hashAlgorithmOid,
            hash($hash, $issuer->subjectNameDer(), true),
            hash($hash, $issuer->subjectPublicKeyBytes(), true),
            $subject->serialNumber(),
        );
    }

    /**
     * @param array<mixed> $mapped the asn1map output of a CertID
     *
     * @internal
     */
    public static function fromMapped(array $mapped): self
    {
        $algorithm = $mapped['hashAlgorithm'] ?? null;
        $oid = \is_array($algorithm) ? ($algorithm['algorithm'] ?? null) : null;
        $nameHash = $mapped['issuerNameHash'] ?? null;
        $keyHash = $mapped['issuerKeyHash'] ?? null;
        $serial = $mapped['serialNumber'] ?? null;
        if (!\is_string($oid) || !\is_string($nameHash) || !\is_string($keyHash) || !$serial instanceof BigInteger) {
            throw new Asn1Exception('Malformed CertID');
        }

        return new self(Oids::dotted($oid), $nameHash, $keyHash, $serial->toString());
    }

    /**
     * @return array<string, mixed> value for the CERT_ID map
     *
     * @internal
     */
    public function toMapped(): array
    {
        return [
            'hashAlgorithm' => ['algorithm' => $this->hashAlgorithmOid],
            'issuerNameHash' => $this->issuerNameHash,
            'issuerKeyHash' => $this->issuerKeyHash,
            'serialNumber' => new BigInteger($this->serialNumber),
        ];
    }

    public function equals(CertId $other): bool
    {
        return $this->hashAlgorithmOid === $other->hashAlgorithmOid
            && hash_equals($this->issuerNameHash, $other->issuerNameHash)
            && hash_equals($this->issuerKeyHash, $other->issuerKeyHash)
            && $this->serialNumber === $other->serialNumber;
    }

    private static function phpHash(string $oid): string
    {
        return match ($oid) {
            Oids::SHA1 => 'sha1',
            Oids::SHA256 => 'sha256',
            Oids::SHA384 => 'sha384',
            Oids::SHA512 => 'sha512',
            default => throw new UnsupportedAlgorithmException(\sprintf('Unsupported CertID hash algorithm %s', $oid)),
        };
    }
}
