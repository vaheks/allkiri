<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Pki;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\KeyPair;

/**
 * A CA certificate with its key, for {@see TestCertificates::issue()}.
 */
final readonly class TestIssuer
{
    public function __construct(
        public Certificate $certificate,
        public TestKey $key,
    ) {}

    /**
     * The committed test CA.
     */
    public static function ca(): self
    {
        return new self(TestPki::ca()->certificate, TestKey::fixture('ca'));
    }

    /**
     * A CA certificate issued in a test, as the issuer of certificates below it.
     */
    public static function of(KeyPair $issued, TestKey $key): self
    {
        return new self($issued->certificate, $key);
    }
}
