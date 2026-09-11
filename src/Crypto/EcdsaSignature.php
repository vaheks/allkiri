<?php

declare(strict_types=1);

namespace Allkiri\Crypto;

use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\Formats\Signature\ASN1 as DerSignature;
use phpseclib3\Math\BigInteger;

/**
 * ECDSA signature value formats.
 *
 * XML-DSig, Web eID, Mobile-ID and Smart-ID carry ECDSA values as the raw
 * concatenation r‖s, each zero-padded to the curve's field size. X.509, CMS
 * and OCSP carry them as a DER SEQUENCE of two INTEGERs.
 */
final class EcdsaSignature
{
    private function __construct() {}

    /**
     * Bytes needed for one field element on the key's curve: 32 (P-256), 48 (P-384) or 66 (P-521).
     */
    public static function fieldBytes(EC $key): int
    {
        $curve = $key->getCurve();
        if (!\is_string($curve)) {
            throw new UnsupportedAlgorithmException('EC keys with explicit curve parameters are not supported');
        }

        return self::fieldBytesForCurve($curve);
    }

    public static function fieldBytesForCurve(string $curve): int
    {
        return match (strtolower($curve)) {
            'secp256r1', 'prime256v1', 'nistp256', 'p-256' => 32,
            'secp384r1', 'nistp384', 'p-384' => 48,
            'secp521r1', 'nistp521', 'p-521' => 66,
            default => throw new UnsupportedAlgorithmException(\sprintf('Unsupported elliptic curve "%s"', $curve)),
        };
    }

    /**
     * r‖s → DER SEQUENCE { INTEGER r, INTEGER s }.
     */
    public static function rawToDer(string $raw): string
    {
        $length = \strlen($raw);
        if ($length === 0 || $length % 2 !== 0) {
            throw new CryptoException(\sprintf('Raw ECDSA signature must have an even length, got %d bytes', $length));
        }
        $half = intdiv($length, 2);
        $r = new BigInteger(substr($raw, 0, $half), 256);
        $s = new BigInteger(substr($raw, $half), 256);

        return Phpseclib::string(DerSignature::save($r, $s));
    }

    /**
     * DER SEQUENCE { INTEGER r, INTEGER s } → r‖s padded to the field size.
     */
    public static function derToRaw(string $der, int $fieldBytes): string
    {
        $parts = DerSignature::load($der);
        if (!\is_array($parts) || !isset($parts['r'], $parts['s'])) {
            throw new CryptoException('Not a DER-encoded ECDSA signature');
        }

        return self::pad(Phpseclib::bigInteger($parts['r']), $fieldBytes) . self::pad(Phpseclib::bigInteger($parts['s']), $fieldBytes);
    }

    /**
     * Whatever an eID means handed back → the raw r‖s form everything in this
     * library verifies and embeds.
     *
     * Mobile-ID returns DER, Web eID returns raw, Smart-ID returns raw, and
     * card middleware has been seen doing either, so the shape is detected
     * rather than assumed.
     *
     * @throws CryptoException when the value is neither, or is the wrong size
     *                         for the curve
     */
    public static function toRaw(string $signature, EC $key): string
    {
        if ($signature === '') {
            throw new CryptoException('The ECDSA signature value is empty');
        }
        $fieldBytes = self::fieldBytes($key);
        if (self::looksLikeDer($signature)) {
            return self::derToRaw($signature, $fieldBytes);
        }
        if (\strlen($signature) !== 2 * $fieldBytes) {
            throw new CryptoException(\sprintf('An ECDSA signature on this curve must be %d bytes, got %d', 2 * $fieldBytes, \strlen($signature)));
        }

        return $signature;
    }

    /**
     * True when the bytes have the shape of a DER SEQUENCE of two INTEGERs.
     * A raw r‖s value of the same length practically never satisfies this.
     */
    public static function looksLikeDer(string $signature): bool
    {
        $length = \strlen($signature);
        if ($length < 8 || $signature[0] !== "\x30") {
            return false;
        }
        $declared = \ord($signature[1]);
        if ($declared < 0x80) {
            return $declared === $length - 2 && $signature[2] === "\x02";
        }
        if ($declared === 0x81) {
            return \ord($signature[2]) === $length - 3 && $signature[3] === "\x02";
        }

        return false;
    }

    private static function pad(BigInteger $value, int $fieldBytes): string
    {
        $bytes = ltrim($value->toBytes(), "\0");
        if (\strlen($bytes) > $fieldBytes) {
            throw new CryptoException(\sprintf('ECDSA signature component is %d bytes, field size is %d', \strlen($bytes), $fieldBytes));
        }

        return str_pad($bytes, $fieldBytes, "\0", STR_PAD_LEFT);
    }
}
