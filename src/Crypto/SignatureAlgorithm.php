<?php

declare(strict_types=1);

namespace Allkiri\Crypto;

use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\EC;

/**
 * Signature algorithms in JWS naming, which is also what Web eID reports as
 * the card's supported algorithms.
 *
 * RS* = RSASSA-PKCS1-v1_5, PS* = RSASSA-PSS (MGF1 with the same hash, salt
 * length = digest length, per RFC 6931), ES* = ECDSA with r‖s signature values.
 */
enum SignatureAlgorithm: string
{
    case RS256 = 'RS256';
    case RS384 = 'RS384';
    case RS512 = 'RS512';
    case PS256 = 'PS256';
    case PS384 = 'PS384';
    case PS512 = 'PS512';
    case ES256 = 'ES256';
    case ES384 = 'ES384';
    case ES512 = 'ES512';

    public function hash(): HashAlgorithm
    {
        return match (substr($this->value, 2)) {
            '256' => HashAlgorithm::SHA256,
            '384' => HashAlgorithm::SHA384,
            default => HashAlgorithm::SHA512,
        };
    }

    public function keyType(): KeyType
    {
        return str_starts_with($this->value, 'ES') ? KeyType::EC : KeyType::RSA;
    }

    public function isPss(): bool
    {
        return str_starts_with($this->value, 'PS');
    }

    /**
     * ds:SignatureMethod/@Algorithm.
     */
    public function xmlUri(): string
    {
        $bits = substr($this->value, 2);

        return match ($this->value[0]) {
            'R' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha' . $bits,
            'P' => 'http://www.w3.org/2007/05/xmldsig-more#sha' . $bits . '-rsa-MGF1',
            default => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha' . $bits,
        };
    }

    /**
     * X.509 / CMS signature algorithm OID, or null for PSS whose OID needs parameters.
     */
    public function oid(): ?string
    {
        $bits = substr($this->value, 2);

        return match ($this->value[0]) {
            'R' => match ($bits) {
                '256' => '1.2.840.113549.1.1.11',
                '384' => '1.2.840.113549.1.1.12',
                default => '1.2.840.113549.1.1.13',
            },
            'E' => match ($bits) {
                '256' => '1.2.840.10045.4.3.2',
                '384' => '1.2.840.10045.4.3.3',
                default => '1.2.840.10045.4.3.4',
            },
            default => null,
        };
    }

    public static function fromXmlUri(string $uri): self
    {
        return self::tryFromXmlUri($uri) ?? throw new UnsupportedAlgorithmException(\sprintf('Unsupported signature algorithm "%s"', $uri));
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

    /**
     * The natural algorithm for a key: ECDSA with the hash matching the
     * curve size (what Estonian cards and digidoc4j use), RSA with SHA-256.
     *
     * @param HashAlgorithm|null $hash overrides the hash; for EC keys any of
     *                                 the three is valid XML-DSig
     */
    public static function forKey(PublicKey $key, bool $preferPss = false, ?HashAlgorithm $hash = null): self
    {
        if ($key instanceof EC\PublicKey) {
            $hash ??= match (EcdsaSignature::fieldBytes($key)) {
                32 => HashAlgorithm::SHA256,
                48 => HashAlgorithm::SHA384,
                default => HashAlgorithm::SHA512,
            };
            $prefix = 'ES';
        } else {
            KeyType::of($key); // throws for anything but RSA
            $hash ??= HashAlgorithm::SHA256;
            $prefix = $preferPss ? 'PS' : 'RS';
        }

        return self::from($prefix . substr($hash->value, 3));
    }
}
