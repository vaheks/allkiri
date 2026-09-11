<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Crypto;

use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\UnsupportedAlgorithmException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(HashAlgorithm::class)]
final class HashAlgorithmTest extends TestCase
{
    public function testIdentifiersRoundTrip(): void
    {
        foreach (HashAlgorithm::cases() as $algorithm) {
            self::assertSame($algorithm, HashAlgorithm::fromXmlUri($algorithm->xmlUri()));
            self::assertSame($algorithm, HashAlgorithm::fromOid($algorithm->oid()));
            self::assertSame($algorithm->digestLength(), \strlen($algorithm->digest('x')));
        }
        self::assertSame('http://www.w3.org/2001/04/xmlenc#sha256', HashAlgorithm::SHA256->xmlUri());
        self::assertSame('http://www.w3.org/2001/04/xmldsig-more#sha384', HashAlgorithm::SHA384->xmlUri());
        self::assertSame('2.16.840.1.101.3.4.2.3', HashAlgorithm::SHA512->oid());
    }

    public function testDigestMatchesPhpHash(): void
    {
        self::assertSame(hash('sha384', 'allkiri', true), HashAlgorithm::SHA384->digest('allkiri'));
    }

    public function testNamesForRemoteServices(): void
    {
        self::assertSame('SHA256', HashAlgorithm::SHA256->name());
        self::assertSame('SHA-512', HashAlgorithm::SHA512->name(dashed: true));
    }

    public function testUnknownIdentifiersAreRejected(): void
    {
        self::assertNull(HashAlgorithm::tryFromXmlUri('http://www.w3.org/2000/09/xmldsig#sha1'));
        self::assertNull(HashAlgorithm::tryFromOid('1.3.14.3.2.26'));

        $this->expectException(UnsupportedAlgorithmException::class);
        HashAlgorithm::fromXmlUri('http://www.w3.org/2000/09/xmldsig#sha1');
    }
}
