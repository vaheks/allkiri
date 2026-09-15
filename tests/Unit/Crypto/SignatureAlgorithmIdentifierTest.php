<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Crypto;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\KeyType;
use Allkiri\Crypto\SignatureAlgorithmIdentifier;
use Allkiri\Crypto\UnsupportedAlgorithmException;
use Allkiri\Tests\Support\Pki\Asn1Encoders;
use Allkiri\Tests\Support\Pki\TestPki;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(SignatureAlgorithmIdentifier::class)]
final class SignatureAlgorithmIdentifierTest extends TestCase
{
    private const CERTS = __DIR__ . '/../../fixtures/certs/';

    public function testCertificatesNameAlgorithmsItKnows(): void
    {
        $rsa = TestPki::signerEc256()->certificate->signatureAlgorithm();
        self::assertSame('1.2.840.113549.1.1.11', $rsa->oid);
        self::assertSame(KeyType::RSA, $rsa->keyType);
        self::assertSame(HashAlgorithm::SHA256, $rsa->hash());

        $ec = Certificate::fromPem((string) file_get_contents(self::CERTS . 'TEST_of_ESTEID2018.pem'))->signatureAlgorithm();
        self::assertSame(KeyType::EC, $ec->keyType);
        self::assertSame(HashAlgorithm::SHA512, $ec->hash());
    }

    /**
     * RSA algorithm identifiers carry an explicit NULL, ECDSA ones nothing, and
     * RFC 4055 asks for both to be accepted either way.
     */
    public function testNullAndAbsentParametersAreBothRead(): void
    {
        self::assertSame('sha384', SignatureAlgorithmIdentifier::fromDer(Asn1Encoders::algorithmIdentifier('1.2.840.113549.1.1.12', true))->hashName);
        self::assertSame('sha384', SignatureAlgorithmIdentifier::fromDer(Asn1Encoders::algorithmIdentifier('1.2.840.113549.1.1.12'))->hashName);
    }

    /**
     * SHA-1 can still be verified, so a signature made with it is reported as
     * weak rather than as unreadable; it just has no hash allkiri accepts.
     */
    public function testSha1IsKnownButHasNoAcceptableHash(): void
    {
        $sha1 = SignatureAlgorithmIdentifier::fromOid('1.2.840.10045.4.1');

        self::assertSame(KeyType::EC, $sha1->keyType);
        self::assertSame('sha1', $sha1->hashName);
        self::assertNull($sha1->hash());
        self::assertTrue(SignatureAlgorithmIdentifier::isKnownOid('1.2.840.113549.1.1.5'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unsupported(): iterable
    {
        yield 'an unknown algorithm' => [Asn1Encoders::algorithmIdentifier('1.2.840.113549.1.1.14', true)];
        yield 'RSASSA-PSS without its parameters' => [Asn1Encoders::algorithmIdentifier('1.2.840.113549.1.1.10')];
        yield 'not a SEQUENCE' => ["\x05\x00"];
        yield 'trailing bytes' => [Asn1Encoders::algorithmIdentifier('1.2.840.113549.1.1.11', true) . "\x00"];
    }

    #[DataProvider('unsupported')]
    public function testAnythingElseIsUnsupported(string $der): void
    {
        $this->expectException(UnsupportedAlgorithmException::class);

        SignatureAlgorithmIdentifier::fromDer($der);
    }
}
