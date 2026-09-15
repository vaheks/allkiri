<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Crypto;

use Allkiri\Crypto\Asn1\Asn1;
use Allkiri\Crypto\Certificate;
use phpseclib3\File\ASN1 as PhpseclibAsn1;

/**
 * Byte patches for structures that must still parse, so that a test reaches
 * the one defect it is about rather than a decoding error before it.
 */
final class DerPatch
{
    private const EC_PUBLIC_KEY = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
    private const RSA_ENCRYPTION = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";

    private function __construct() {}

    /**
     * Replace bytes that occur exactly once, and fail loudly when they do not.
     */
    public static function replaceOnce(string $der, string $search, string $replace): string
    {
        $count = substr_count($der, $search);
        if ($count !== 1) {
            throw new \LogicException(\sprintf('Expected the bytes to occur once, found them %d times', $count));
        }

        return str_replace($search, $replace, $der);
    }

    /**
     * The certificate with its public key algorithm renamed to one nothing
     * knows: it still parses, but its key cannot be loaded. Its issuer's
     * signature no longer holds, which the tests that use this do not reach.
     */
    public static function unreadableKey(Certificate $certificate): Certificate
    {
        $der = $certificate->der();
        $algorithm = str_contains($der, self::EC_PUBLIC_KEY) ? self::EC_PUBLIC_KEY : self::RSA_ENCRYPTION;

        return Certificate::fromDer(self::replaceOnce($der, $algorithm, substr($algorithm, 0, -1) . "\x7f"));
    }

    /**
     * The structure with a certificate's bytes replaced by a SEQUENCE of the
     * same length that is not a certificate, so every length around it holds.
     */
    public static function withoutCertificate(string $der, Certificate $certificate): string
    {
        $length = \strlen($certificate->der());
        for ($filler = $length - 2; $filler > 0; --$filler) {
            $impostor = Asn1::sequence([Asn1::primitive(PhpseclibAsn1::TYPE_OCTET_STRING, str_repeat("\x00", $filler))]);
            if (\strlen($impostor) === $length) {
                return self::replaceOnce($der, $certificate->der(), $impostor);
            }
        }

        throw new \LogicException('No SEQUENCE has that length');
    }
}
