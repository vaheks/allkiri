<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Crypto;

use Allkiri\Crypto\AlgorithmConstraints;
use Allkiri\Crypto\SignatureAlgorithmIdentifier;
use Allkiri\Tests\Support\Pki\TestKey;
use Allkiri\Tests\Support\Pki\TestPki;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AlgorithmConstraints::class)]
final class AlgorithmConstraintsTest extends TestCase
{
    private const SHA256_WITH_RSA = '1.2.840.113549.1.1.11';

    public function testSha1IsRefusedWhateverTheKey(): void
    {
        $violation = (new AlgorithmConstraints())->violation(SignatureAlgorithmIdentifier::fromOid('1.2.840.113549.1.1.5'), TestPki::ca()->certificate->publicKey());

        self::assertSame('signed with SHA-1, which is no longer accepted', $violation);
    }

    public function testAnRsaKeyBelowTheMinimumIsRefused(): void
    {
        $algorithm = SignatureAlgorithmIdentifier::fromOid(self::SHA256_WITH_RSA);
        $constraints = new AlgorithmConstraints();

        self::assertNull($constraints->violation($algorithm, TestPki::signerRsa()->certificate->publicKey()), 'a 2048-bit key meets the default');
        self::assertSame(
            'signed with a 1024-bit RSA key, where at least 2048 bits are required',
            $constraints->violation($algorithm, TestKey::rsa(1024)->publicKey()),
        );
        // The test CA's key is 3072 bits.
        self::assertNotNull((new AlgorithmConstraints(4096))->violation($algorithm, TestPki::ca()->certificate->publicKey()));
    }

    public function testEllipticCurveKeysHaveNoSizeFloor(): void
    {
        $violation = (new AlgorithmConstraints(4096))->violation(SignatureAlgorithmIdentifier::fromOid('1.2.840.10045.4.3.2'), TestPki::signerEc256()->certificate->publicKey());

        self::assertNull($violation);
    }
}
