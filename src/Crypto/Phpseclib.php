<?php

declare(strict_types=1);

namespace Allkiri\Crypto;

use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use phpseclib3\Math\BigInteger;

/**
 * phpseclib's fluent API declares no return types, so every chained call is
 * "mixed" to static analysis. These guards turn each result back into the
 * concrete type it always is in practice, and fail loudly if it ever is not.
 *
 * @internal
 */
final class Phpseclib
{
    private function __construct() {}

    public static function rsaPublic(mixed $value): RSA\PublicKey
    {
        return $value instanceof RSA\PublicKey ? $value : throw self::unexpected('RSA public key', $value);
    }

    public static function ecPublic(mixed $value): EC\PublicKey
    {
        return $value instanceof EC\PublicKey ? $value : throw self::unexpected('EC public key', $value);
    }

    public static function rsaPrivate(mixed $value): RSA\PrivateKey
    {
        return $value instanceof RSA\PrivateKey ? $value : throw self::unexpected('RSA private key', $value);
    }

    public static function ecPrivate(mixed $value): EC\PrivateKey
    {
        return $value instanceof EC\PrivateKey ? $value : throw self::unexpected('EC private key', $value);
    }

    public static function bigInteger(mixed $value): BigInteger
    {
        return $value instanceof BigInteger ? $value : throw self::unexpected('big integer', $value);
    }

    public static function string(mixed $value): string
    {
        return \is_string($value) ? $value : throw self::unexpected('string', $value);
    }

    public static function bool(mixed $value): bool
    {
        return \is_bool($value) ? $value : throw self::unexpected('bool', $value);
    }

    public static function int(mixed $value): int
    {
        return \is_int($value) ? $value : throw self::unexpected('int', $value);
    }

    private static function unexpected(string $expected, mixed $value): CryptoException
    {
        return new CryptoException(\sprintf('phpseclib returned %s where %s was expected', get_debug_type($value), $expected));
    }
}
