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

    /**
     * Runs a phpseclib call on bytes a stranger supplied, with its warnings
     * raised as exceptions.
     *
     * phpseclib's decoders assume the input has the shape they expect. On one
     * that does not, they index into what is not there and PHP warns, then
     * carry on, and sometimes stop with a TypeError further in. An application
     * whose error handler turns warnings into exceptions, as Laravel's and
     * Symfony's do, would see those escape from a validator that promises a
     * report instead. Here a warning ends the call wherever the application's
     * handler stands, and the caller turns whatever ended it into its own
     * exception. Deprecations and the rest pass to PHP's own handling.
     *
     * @template T
     *
     * @param \Closure(): T $call
     *
     * @throws \Throwable what phpseclib threw, or a CryptoException for a warning or notice it raised
     *
     * @return T
     */
    public static function onUntrustedInput(\Closure $call): mixed
    {
        set_error_handler(static function (int $level, string $message): never {
            throw new CryptoException('phpseclib could not read its input: ' . $message);
        }, E_WARNING | E_NOTICE | E_USER_WARNING | E_USER_NOTICE);
        try {
            return $call();
        } finally {
            restore_error_handler();
        }
    }

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
