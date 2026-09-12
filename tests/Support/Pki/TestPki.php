<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Pki;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\KeyPair;
use Allkiri\Crypto\PrivateKey;

/**
 * The committed test PKI under tests/fixtures/pki (see generate.sh there).
 *
 * All certificates are issued by one root CA and valid 2020-01-01 to
 * 2050-01-01, so tests with a frozen clock anywhere in that window work.
 */
final class TestPki
{
    public const DIR = __DIR__ . '/../../fixtures/pki';

    private function __construct() {}

    public static function ca(): KeyPair
    {
        return self::load('ca');
    }

    public static function signerEc256(): KeyPair
    {
        return self::load('signer-ec256');
    }

    public static function signerEc384(): KeyPair
    {
        return self::load('signer-ec384');
    }

    public static function signerRsa(): KeyPair
    {
        return self::load('signer-rsa');
    }

    /**
     * An RSA key whose subject names a person, for Smart-ID: its keys are
     * always RSA, and its certificates put the given name before the surname
     * in the common name.
     */
    public static function signerRsaPerson(): KeyPair
    {
        return self::load('signer-rsa-person');
    }

    /**
     * An ID-card authentication key: elliptic curve P-384 as Estonian cards
     * use, with the client-authentication purpose Web eID requires.
     */
    public static function cardAuth(): KeyPair
    {
        return self::load('card-auth');
    }

    public static function tsa(): KeyPair
    {
        return self::load('tsa');
    }

    public static function ocspResponder(): KeyPair
    {
        return self::load('ocsp');
    }

    public static function certificate(string $name): Certificate
    {
        return Certificate::fromPem(self::read($name . '.cert.pem'));
    }

    private static function load(string $name): KeyPair
    {
        $certificate = self::certificate($name);
        $chain = $name === 'ca' ? [] : [self::certificate('ca')];

        return new KeyPair(PrivateKey::fromPem(self::read($name . '.key.pem')), $certificate, $chain);
    }

    private static function read(string $file): string
    {
        $path = self::DIR . '/' . $file;
        $content = file_get_contents($path);
        if ($content === false) {
            throw new \RuntimeException('Missing test PKI fixture ' . $path . '; run tests/fixtures/pki/generate.sh');
        }

        return $content;
    }
}
