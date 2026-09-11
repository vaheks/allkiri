<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Crypto;

use Allkiri\Crypto\CryptoException;
use Allkiri\Crypto\EcdsaSignature;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Crypto\UnsupportedAlgorithmException;
use Allkiri\Tests\Support\Pki\TestPki;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(EcdsaSignature::class)]
final class EcdsaSignatureTest extends TestCase
{
    public function testFieldSizesByCurveName(): void
    {
        self::assertSame(32, EcdsaSignature::fieldBytesForCurve('secp256r1'));
        self::assertSame(32, EcdsaSignature::fieldBytesForCurve('prime256v1'));
        self::assertSame(48, EcdsaSignature::fieldBytesForCurve('nistp384'));
        self::assertSame(66, EcdsaSignature::fieldBytesForCurve('P-521'));

        $this->expectException(UnsupportedAlgorithmException::class);
        EcdsaSignature::fieldBytesForCurve('brainpoolP256r1');
    }

    public function testRawAndDerRoundTripForBothCurves(): void
    {
        foreach ([[TestPki::signerEc256(), SignatureAlgorithm::ES256, 32], [TestPki::signerEc384(), SignatureAlgorithm::ES384, 48]] as [$pair, $algorithm, $fieldBytes]) {
            $raw = $pair->privateKey->sign($algorithm, 'payload');
            self::assertSame(2 * $fieldBytes, \strlen($raw));
            self::assertFalse(EcdsaSignature::looksLikeDer($raw));

            $der = EcdsaSignature::rawToDer($raw);
            self::assertTrue(EcdsaSignature::looksLikeDer($der));
            self::assertSame($raw, EcdsaSignature::derToRaw($der, $fieldBytes));
        }
    }

    public function testLeadingZeroComponentsKeepTheirWidth(): void
    {
        // r starts with 0x00: DER encodes it shorter, raw form must pad it back.
        $raw = "\x00\x00" . str_repeat("\x11", 30) . "\x7f" . str_repeat("\x22", 31);
        $der = EcdsaSignature::rawToDer($raw);

        self::assertSame($raw, EcdsaSignature::derToRaw($der, 32));
    }

    public function testMalformedInputIsRejected(): void
    {
        self::assertFalse(EcdsaSignature::looksLikeDer('short'));
        self::assertFalse(EcdsaSignature::looksLikeDer(str_repeat("\x30", 64)));

        try {
            EcdsaSignature::rawToDer(str_repeat('a', 63));
            self::fail('odd length accepted');
        } catch (CryptoException) {
        }

        $this->expectException(CryptoException::class);
        EcdsaSignature::derToRaw("\x30\x02\x05\x00", 32);
    }
}
