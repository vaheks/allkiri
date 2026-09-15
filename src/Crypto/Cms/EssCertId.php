<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Cms;

use Allkiri\Crypto\Asn1\Asn1Exception;
use Allkiri\Crypto\Asn1\Oids;
use Allkiri\Crypto\Certificate;
use phpseclib3\Math\BigInteger;

/**
 * One ESSCertIDv2 (RFC 5035) or legacy ESSCertID (RFC 2634, SHA-1): the
 * signer's commitment to a particular certificate.
 */
final readonly class EssCertId
{
    public function __construct(
        public string $hashAlgorithmOid,
        public string $certHash,
        public ?string $issuerSerial,
    ) {}

    /**
     * @param array<mixed> $mapped one element of SigningCertificate(V2).certs
     *
     * @internal
     */
    public static function fromMapped(array $mapped, bool $v2): self
    {
        $hash = $mapped['certHash'] ?? null;
        if (!\is_string($hash)) {
            throw new Asn1Exception('Malformed ESSCertID');
        }
        $oid = Oids::SHA1;
        if ($v2) {
            $algorithm = $mapped['hashAlgorithm'] ?? null;
            $oid = \is_array($algorithm) && \is_string($algorithm['algorithm'] ?? null) ? Oids::dotted($algorithm['algorithm']) : Oids::SHA256;
        }
        $serial = null;
        $issuerSerial = $mapped['issuerSerial'] ?? null;
        if (\is_array($issuerSerial) && ($issuerSerial['serialNumber'] ?? null) instanceof BigInteger) {
            $serial = $issuerSerial['serialNumber']->toString();
        }

        return new self($oid, $hash, $serial);
    }

    public function matches(Certificate $certificate): bool
    {
        $php = match ($this->hashAlgorithmOid) {
            Oids::SHA1 => 'sha1',
            Oids::SHA256 => 'sha256',
            Oids::SHA384 => 'sha384',
            Oids::SHA512 => 'sha512',
            default => null,
        };
        if ($php === null || !hash_equals(hash($php, $certificate->der(), true), $this->certHash)) {
            return false;
        }

        return $this->issuerSerial === null || $this->issuerSerial === $certificate->serialNumber();
    }
}
