<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Crypto;

use Allkiri\Crypto\Asn1\Asn1;
use Allkiri\Crypto\Asn1\Oids;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\PssParameters;
use Allkiri\Crypto\UnsupportedAlgorithmException;
use Allkiri\Tests\Support\Pki\Asn1Encoders;
use phpseclib3\File\ASN1 as PhpseclibAsn1;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(PssParameters::class)]
final class PssParametersTest extends TestCase
{
    /**
     * @return iterable<string, array{string, HashAlgorithm}>
     */
    public static function accepted(): iterable
    {
        foreach (HashAlgorithm::cases() as $hash) {
            yield $hash->name(true) => [self::parameters(self::hash($hash->oid()), self::mgf1($hash->oid()), self::salt($hash->digestLength())), $hash];
        }
        yield 'hash parameters left out rather than NULL' => [self::parameters(self::hash(Oids::SHA256, false), self::mgf1(Oids::SHA256, false), self::salt(32)), HashAlgorithm::SHA256];
        yield 'the trailer field written out' => [self::parameters(self::hash(Oids::SHA256), self::mgf1(Oids::SHA256), self::salt(32), Asn1::explicit(3, Asn1::integer(1))), HashAlgorithm::SHA256];
    }

    #[DataProvider('accepted')]
    public function testTheProfileInUseIsAccepted(string $der, HashAlgorithm $hash): void
    {
        $parameters = PssParameters::fromDer($der);

        self::assertSame($hash, $parameters->hash);
        self::assertSame($hash->digestLength(), $parameters->saltLength);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function refused(): iterable
    {
        yield 'no hash, which means SHA-1' => [self::parameters(self::mgf1(Oids::SHA256), self::salt(32))];
        yield 'SHA-1 named' => [self::parameters(self::hash(Oids::SHA1), self::mgf1(Oids::SHA1), self::salt(20))];
        yield 'no mask generation function, which means MGF1 with SHA-1' => [self::parameters(self::hash(Oids::SHA256), self::salt(32))];
        yield 'a mask generation hash other than the digest' => [self::parameters(self::hash(Oids::SHA256), self::mgf1(Oids::SHA512), self::salt(32))];
        yield 'a mask generation function other than MGF1' => [self::parameters(
            self::hash(Oids::SHA256),
            Asn1::explicit(1, Asn1::sequence([Asn1::primitive(PhpseclibAsn1::TYPE_OBJECT_IDENTIFIER, '1.2.3.4'), Asn1Encoders::algorithmIdentifier(Oids::SHA256, true)])),
            self::salt(32),
        )];
        yield 'no salt length, which means 20' => [self::parameters(self::hash(Oids::SHA256), self::mgf1(Oids::SHA256))];
        yield 'a salt shorter than the digest' => [self::parameters(self::hash(Oids::SHA256), self::mgf1(Oids::SHA256), self::salt(20))];
        yield 'a salt longer than the digest' => [self::parameters(self::hash(Oids::SHA256), self::mgf1(Oids::SHA256), self::salt(64))];
        yield 'a trailer field other than 1' => [self::parameters(self::hash(Oids::SHA256), self::mgf1(Oids::SHA256), self::salt(32), Asn1::explicit(3, Asn1::integer(2)))];
        yield 'fields out of order' => [self::parameters(self::mgf1(Oids::SHA256), self::hash(Oids::SHA256), self::salt(32))];
        yield 'hash parameters that are not NULL' => [self::parameters(Asn1::explicit(0, Asn1::sequence([Asn1::primitive(PhpseclibAsn1::TYPE_OBJECT_IDENTIFIER, Oids::SHA256), Asn1::integer(1)])), self::mgf1(Oids::SHA256), self::salt(32))];
        yield 'trailing bytes' => [self::parameters(self::hash(Oids::SHA256), self::mgf1(Oids::SHA256), self::salt(32)) . "\x00"];
        yield 'not a SEQUENCE' => ["\x05\x00"];
    }

    #[DataProvider('refused')]
    public function testAnythingElseIsUnsupported(string $der): void
    {
        $this->expectException(UnsupportedAlgorithmException::class);

        PssParameters::fromDer($der);
    }

    private static function parameters(string ...$fields): string
    {
        return Asn1::sequence(array_values($fields));
    }

    private static function hash(string $oid, bool $nullParameters = true): string
    {
        return Asn1::explicit(0, Asn1Encoders::algorithmIdentifier($oid, $nullParameters));
    }

    private static function mgf1(string $hashOid, bool $nullParameters = true): string
    {
        return Asn1::explicit(1, Asn1::sequence([
            Asn1::primitive(PhpseclibAsn1::TYPE_OBJECT_IDENTIFIER, Oids::MGF1),
            Asn1Encoders::algorithmIdentifier($hashOid, $nullParameters),
        ]));
    }

    private static function salt(int $length): string
    {
        return Asn1::explicit(2, Asn1::integer($length));
    }
}
