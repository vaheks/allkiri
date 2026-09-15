<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Pki;

/**
 * How {@see TestCertificates::issue()} signs a certificate.
 */
enum TestCertificateSignature
{
    /** What every committed certificate uses. */
    case Sha256;

    /** SHA-1, which allkiri still verifies but no longer accepts. */
    case Sha1;

    /** RSASSA-PSS with SHA-256, MGF1 with SHA-256 and a 32-byte salt: the profile allkiri accepts. */
    case Pss256;

    /** RSASSA-PSS with SHA-256 and a 20-byte salt, which allkiri refuses. */
    case Pss256Salt20;

    public function hashName(): string
    {
        return match ($this) {
            self::Sha1 => 'sha1',
            self::Sha256, self::Pss256, self::Pss256Salt20 => 'sha256',
        };
    }

    /**
     * The RSASSA-PSS salt length, or null for signatures that are not PSS.
     */
    public function pssSaltLength(): ?int
    {
        return match ($this) {
            self::Pss256 => 32,
            self::Pss256Salt20 => 20,
            self::Sha256, self::Sha1 => null,
        };
    }
}
