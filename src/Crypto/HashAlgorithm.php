<?php

declare(strict_types=1);

namespace Allkiri\Crypto;

/**
 * The digest algorithms allkiri emits and accepts. SHA-1 is deliberately
 * absent: signatures using it are reported by the validator, never produced.
 */
enum HashAlgorithm: string
{
    case SHA256 = 'sha256';
    case SHA384 = 'sha384';
    case SHA512 = 'sha512';

    /**
     * XML-DSig / XML-Enc algorithm identifier.
     */
    public function xmlUri(): string
    {
        return match ($this) {
            self::SHA256 => 'http://www.w3.org/2001/04/xmlenc#sha256',
            self::SHA384 => 'http://www.w3.org/2001/04/xmldsig-more#sha384',
            self::SHA512 => 'http://www.w3.org/2001/04/xmlenc#sha512',
        };
    }

    /**
     * NIST hash algorithm OID (RFC 5754).
     */
    public function oid(): string
    {
        return match ($this) {
            self::SHA256 => '2.16.840.1.101.3.4.2.1',
            self::SHA384 => '2.16.840.1.101.3.4.2.2',
            self::SHA512 => '2.16.840.1.101.3.4.2.3',
        };
    }

    public function digestLength(): int
    {
        return match ($this) {
            self::SHA256 => 32,
            self::SHA384 => 48,
            self::SHA512 => 64,
        };
    }

    /**
     * Name used by the Mobile-ID REST API ("SHA256") and by Web eID ("SHA-256" when dashed).
     */
    public function name(bool $dashed = false): string
    {
        $bits = substr($this->value, 3);

        return 'SHA' . ($dashed ? '-' : '') . $bits;
    }

    /**
     * Binary digest of the data.
     */
    public function digest(string $data): string
    {
        return hash($this->value, $data, true);
    }

    public static function fromXmlUri(string $uri): self
    {
        return self::tryFromXmlUri($uri) ?? throw new UnsupportedAlgorithmException(\sprintf('Unsupported digest algorithm "%s"', $uri));
    }

    public static function tryFromXmlUri(string $uri): ?self
    {
        foreach (self::cases() as $case) {
            if ($case->xmlUri() === $uri) {
                return $case;
            }
        }

        return null;
    }

    public static function fromOid(string $oid): self
    {
        return self::tryFromOid($oid) ?? throw new UnsupportedAlgorithmException(\sprintf('Unsupported digest algorithm OID "%s"', $oid));
    }

    public static function tryFromOid(string $oid): ?self
    {
        foreach (self::cases() as $case) {
            if ($case->oid() === $oid) {
                return $case;
            }
        }

        return null;
    }
}
