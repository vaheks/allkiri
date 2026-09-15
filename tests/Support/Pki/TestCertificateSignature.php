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

    public function hashName(): string
    {
        return match ($this) {
            self::Sha256 => 'sha256',
            self::Sha1 => 'sha1',
        };
    }
}
