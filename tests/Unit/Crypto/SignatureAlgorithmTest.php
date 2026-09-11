<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Crypto;

use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\KeyType;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Crypto\UnsupportedAlgorithmException;
use Allkiri\Tests\Support\Pki\TestPki;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(SignatureAlgorithm::class)]
final class SignatureAlgorithmTest extends TestCase
{
    public function testXmlUrisAreTheOnesValidatorsExpect(): void
    {
        self::assertSame('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', SignatureAlgorithm::RS256->xmlUri());
        self::assertSame('http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1', SignatureAlgorithm::PS256->xmlUri());
        self::assertSame('http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1', SignatureAlgorithm::PS512->xmlUri());
        self::assertSame('http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384', SignatureAlgorithm::ES384->xmlUri());
        foreach (SignatureAlgorithm::cases() as $algorithm) {
            self::assertSame($algorithm, SignatureAlgorithm::fromXmlUri($algorithm->xmlUri()));
        }
    }

    public function testPropertiesFollowTheJwsName(): void
    {
        self::assertSame(HashAlgorithm::SHA384, SignatureAlgorithm::PS384->hash());
        self::assertSame(KeyType::RSA, SignatureAlgorithm::PS384->keyType());
        self::assertTrue(SignatureAlgorithm::PS384->isPss());
        self::assertFalse(SignatureAlgorithm::RS384->isPss());
        self::assertSame(KeyType::EC, SignatureAlgorithm::ES512->keyType());
        self::assertSame(HashAlgorithm::SHA512, SignatureAlgorithm::ES512->hash());
    }

    public function testOidsForNonPssAlgorithms(): void
    {
        self::assertSame('1.2.840.113549.1.1.11', SignatureAlgorithm::RS256->oid());
        self::assertSame('1.2.840.10045.4.3.3', SignatureAlgorithm::ES384->oid());
        self::assertNull(SignatureAlgorithm::PS256->oid());
    }

    public function testForKeyFollowsCurveSizeAndRsaPreference(): void
    {
        self::assertSame(SignatureAlgorithm::ES256, SignatureAlgorithm::forKey(TestPki::signerEc256()->certificate->publicKey()));
        self::assertSame(SignatureAlgorithm::ES384, SignatureAlgorithm::forKey(TestPki::signerEc384()->certificate->publicKey()));
        self::assertSame(SignatureAlgorithm::ES512, SignatureAlgorithm::forKey(TestPki::signerEc384()->certificate->publicKey(), hash: HashAlgorithm::SHA512));
        self::assertSame(SignatureAlgorithm::RS256, SignatureAlgorithm::forKey(TestPki::signerRsa()->certificate->publicKey()));
        self::assertSame(SignatureAlgorithm::PS512, SignatureAlgorithm::forKey(TestPki::signerRsa()->certificate->publicKey(), preferPss: true, hash: HashAlgorithm::SHA512));
    }

    public function testUnknownUriIsRejected(): void
    {
        $this->expectException(UnsupportedAlgorithmException::class);
        SignatureAlgorithm::fromXmlUri('http://www.w3.org/2000/09/xmldsig#rsa-sha1');
    }
}
