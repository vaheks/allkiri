<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Crypto\Asn1;

use Allkiri\Crypto\Asn1\Asn1;
use Allkiri\Crypto\Asn1\Asn1Exception;
use Allkiri\Crypto\Asn1\NestingGuard;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\CertificateException;
use Allkiri\Tests\Support\Crypto\DeepDer;
use Allkiri\Tests\Support\Pki\TestPki;
use phpseclib3\File\ASN1 as PhpseclibAsn1;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * phpseclib's decoder runs out of memory, fatally, on DER nested a few
 * thousand levels deep. The guard refuses such DER first, wherever phpseclib
 * would decode it, and has to agree with phpseclib about how deep that is.
 */
#[CoversClass(NestingGuard::class)]
final class NestingGuardTest extends TestCase
{
    /** Set by the instrumented copy of phpseclib's decoder. */
    public static int $depth = 0;

    /** Set by the instrumented copy of phpseclib's decoder. */
    public static int $deepest = 0;

    private static ?\Closure $decoder = null;

    public function testNestingUpToTheLimitDecodesAndOneLevelMoreIsRefused(): void
    {
        $atTheLimit = DeepDer::nested(NestingGuard::MAX_DEPTH - 1);
        self::assertSame(NestingGuard::MAX_DEPTH, NestingGuard::depthOf($atTheLimit));
        self::assertSame($atTheLimit, Asn1::decodeRaw($atTheLimit)->der());

        $this->expectException(Asn1Exception::class);
        $this->expectExceptionMessage('DER nests deeper than 64 levels');

        Asn1::decodeRaw(DeepDer::nested(NestingGuard::MAX_DEPTH));
    }

    public function testTheNestingThatExhaustedMemoryIsRefusedCheaply(): void
    {
        // About 80 KB. Inside phpseclib this exhausted a 128 MB memory limit,
        // which is a fatal error rather than an exception.
        $der = DeepDer::nested(20_000);
        memory_reset_peak_usage();
        $before = memory_get_peak_usage();

        try {
            Asn1::decodeRaw($der);
            self::fail('Twenty thousand levels of nesting were decoded');
        } catch (Asn1Exception) {
        }

        self::assertLessThan(4 * 1024 * 1024, memory_get_peak_usage() - $before);
    }

    public function testNestingHiddenInACertificateExtensionIsRefused(): void
    {
        $der = DeepDer::inBasicConstraints(TestPki::ca()->certificate, DeepDer::nested(20_000));
        self::assertLessThan(10, NestingGuard::depthOf($der), 'the certificate around it is shallow');

        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage('DER nests deeper than 64 levels');

        Certificate::fromDer($der);
    }

    public function testNestingHiddenInAPublicKeyIsRefused(): void
    {
        // phpseclib would only decode this when the key is first used, long
        // after the certificate had been accepted.
        $der = DeepDer::inPublicKey(TestPki::ca()->certificate, DeepDer::nested(20_000));

        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage('DER nests deeper than 64 levels');

        Certificate::fromDer($der);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function quirks(): iterable
    {
        yield 'a length in more than four octets' => ["\x30\x86\x00\x00\x00\x00\x00\x02\x05\x00"];
        yield 'junk in the high length octets' => ["\x30\x86\xFF\xFF\x00\x00\x00\x02\x05\x00"];
        yield 'indefinite lengths' => ["\x30\x80\x30\x80\x05\x00\x00\x00\x00\x00"];
        yield 'a tagged element with a broken first child' => ["\x30\x0E\xA0\x02\x02\x85\x30\x08\x30\x06\x30\x04\x30\x02\x05\x00"];
        yield 'end of contents inside a definite length' => ["\xA0\x08\x05\x00\x00\x00\x30\x02\x05\x00"];
        yield 'a constructed BIT STRING' => ["\x23\x06\x30\x04\x30\x02\x05\x00"];
        yield 'a constructed OCTET STRING' => ["\x24\x80\x24\x80\x04\x00\x00\x00\x00\x00"];
        yield 'a constructed OCTET STRING of the wrong type' => ["\x24\x80\x30\x02\x05\x00\x00\x00"];
        yield 'a high tag number' => ["\xBF\x81\x01\x04\x30\x02\x05\x00"];
        yield 'an object identifier that decodeOID() refuses' => ["\x30\x06\x06\x01\x80\x30\x02\x05\x00"];
        yield 'a type decode_ber() does not know' => ["\x30\x04\x07\x00\x30\x00"];
        yield 'a real certificate' => [TestPki::ca()->certificate->der()];
    }

    #[DataProvider('quirks')]
    public function testTheGuardAgreesWithPhpseclibOnItsQuirks(string $der): void
    {
        $this->assertAgreesWithPhpseclib($der);
    }

    /**
     * The guard is only as good as its agreement with phpseclib. A copy of
     * phpseclib's own decode_ber(), instrumented to count its depth, runs
     * against generated DER, malformed and quirky included, and the two must
     * agree on every input.
     *
     * When a phpseclib upgrade changes decode_ber(), this may fail or the copy
     * may no longer be found. Either way, review NestingGuard against the new
     * decoder before accepting the upgrade.
     */
    public function testTheGuardAgreesWithPhpseclibOnGeneratedDer(): void
    {
        $random = new \Random\Randomizer(new \Random\Engine\Mt19937(20260914));

        for ($case = 0; $case < 3000; ++$case) {
            $this->assertAgreesWithPhpseclib(self::mutate($random, self::element($random, 0)));
        }
    }

    private function assertAgreesWithPhpseclib(string $der): void
    {
        $decode = self::instrumentedDecoder();
        self::$depth = 0;
        self::$deepest = 0;
        $threw = false;
        set_error_handler(static fn(): bool => true);
        try {
            $decode($der);
        } catch (\Throwable) {
            $threw = true;
        } finally {
            restore_error_handler();
        }

        $guard = NestingGuard::depthOf($der);
        if ($threw) {
            // phpseclib stopped early, so the guard may have looked further.
            self::assertGreaterThanOrEqual(self::$deepest, $guard, bin2hex($der));
        } else {
            self::assertSame(self::$deepest, $guard, 'phpseclib and the guard disagree about ' . bin2hex($der));
        }
    }

    /**
     * phpseclib's decode_ber(), copied from the installed version, with a
     * counter around every call.
     */
    private static function instrumentedDecoder(): \Closure
    {
        if (self::$decoder !== null) {
            return self::$decoder;
        }
        $file = (new \ReflectionClass(PhpseclibAsn1::class))->getFileName();
        self::assertIsString($file);
        $found = preg_match(
            '/^    private static function decode_ber\(\$encoded, \$start = 0, \$encoded_pos = 0\)\R    \{\R(.*?)\R    \}\R/sm',
            (string) file_get_contents($file),
            $match,
        );
        self::assertSame(1, $found, 'phpseclib\'s decode_ber() has changed: review NestingGuard against the new decoder');

        $body = strtr($match[1], [
            'self::decode_ber(' => 'self::decodeBer(',
            'self::decodeTime(' => 'self::decodedTime(',
            'self::decodeOID(' => 'parent::decodeOID(',
            'new BigInteger(' => 'new \phpseclib3\Math\BigInteger(',
        ]);
        $source = strtr(<<<'PHP'
            final class AllkiriInstrumentedDecodeBer extends \phpseclib3\File\ASN1
            {
                public static function decodeBer($encoded, $start = 0, $encoded_pos = 0)
                {
                    COUNTER::$deepest = max(COUNTER::$deepest, ++COUNTER::$depth);
                    try {
                        return self::original($encoded, $start, $encoded_pos);
                    } finally {
                        --COUNTER::$depth;
                    }
                }

                private static function decodedTime($content, $tag)
                {
                    return '';
                }

                private static function original($encoded, $start = 0, $encoded_pos = 0)
                {
                    BODY
                }
            }

            return static fn(string $der): mixed => AllkiriInstrumentedDecodeBer::decodeBer($der);
            PHP, ['COUNTER' => '\\' . self::class, 'BODY' => $body]);

        $decoder = eval($source);
        self::assertInstanceOf(\Closure::class, $decoder);

        return self::$decoder = $decoder;
    }

    /**
     * A random element, sometimes well formed, often not in the ways phpseclib
     * reads loosely.
     */
    private static function element(\Random\Randomizer $random, int $level): string
    {
        if ($level >= 6 || $random->getInt(0, 2) === 0) {
            [$identifier, $content] = match ($random->getInt(0, 9)) {
                0 => ["\x02", $random->getBytes($random->getInt(1, 3))],
                1 => ["\x05", ''],
                2 => ["\x04", $level < 6 && $random->getInt(0, 1) === 0 ? self::element($random, $level + 1) : $random->getBytes($random->getInt(1, 4))],
                3 => ["\x06", $random->getInt(0, 1) === 0 ? "\x2A\x03" : $random->getBytes($random->getInt(1, 3))],
                4 => ["\x0C", 'tere'],
                5 => ["\x01", $random->getBytes($random->getInt(1, 2))],
                6 => ["\x03", "\x00" . $random->getBytes($random->getInt(1, 2))],
                7 => ["\x17", '260914120000Z'],
                8 => [\chr($random->getInt(0, 255) & ~0x20), $random->getBytes($random->getInt(1, 3))],
                default => ["\x9F\x81\x05", $random->getBytes(1)],
            };

            return $identifier . self::length($random, \strlen($content)) . $content;
        }

        $identifier = match ($random->getInt(0, 7)) {
            0, 1 => "\x30",
            2 => "\x31",
            3 => "\xA0",
            4 => "\x61",
            5 => "\x24",
            6 => "\x23",
            default => \chr($random->getInt(0, 255) | 0x20),
        };
        $children = '';
        for ($count = $random->getInt(0, 3); $count > 0; --$count) {
            $children .= self::element($random, $level + 1);
        }
        if ($random->getInt(0, 3) === 0) {
            // An indefinite length, usually but not always closed.
            $endOfContents = $random->getInt(1, 4) > 1 ? "\0\0" : '';

            return $identifier . "\x80" . $children . $endOfContents;
        }

        return $identifier . self::length($random, \strlen($children)) . $children;
    }

    private static function length(\Random\Randomizer $random, int $length): string
    {
        $octets = $random->getInt(5, 6);

        return match ($random->getInt(0, 5)) {
            0, 1 => PhpseclibAsn1::encodeLength($length),
            2 => \chr(0x80 | $octets) . str_repeat("\0", $octets - 4) . pack('N', $length),
            3 => \chr(0x80 | $octets) . $random->getBytes($octets - 4) . pack('N', $length),
            4 => PhpseclibAsn1::encodeLength(max(0, $length + $random->getInt(-2, 2))),
            default => "\x81" . \chr($length & 0xFF),
        };
    }

    private static function mutate(\Random\Randomizer $random, string $der): string
    {
        switch ($random->getInt(0, 5)) {
            case 0:
                $at = $random->getInt(0, \strlen($der) - 1);
                $der[$at] = \chr($random->getInt(0, 255));

                return $der;
            case 1:
                return substr($der, 0, $random->getInt(0, \strlen($der)));
            case 2:
                return $der . "\0\0" . $random->getBytes($random->getInt(1, 3));
            default:
                return $der;
        }
    }
}
