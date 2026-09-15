<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Pki;

use Allkiri\Crypto\Phpseclib;
use Allkiri\Crypto\PrivateKey;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;

/**
 * A private key for tests, both as allkiri signs with it and as phpseclib
 * does, for issuing certificates and signing with algorithms allkiri itself
 * never produces.
 *
 * Generated keys are made when first asked for and kept for the run, one per
 * label, so a test can have two different keys of the same kind.
 */
final class TestKey
{
    /** @var array<string, self> */
    private static array $generated = [];

    private function __construct(
        public readonly PrivateKey $privateKey,
        public readonly RSA\PrivateKey|EC\PrivateKey $raw,
    ) {}

    /**
     * A committed key from tests/fixtures/pki, such as "ca" or "ocsp".
     */
    public static function fixture(string $name): self
    {
        $pem = file_get_contents(TestPki::DIR . '/' . $name . '.key.pem');
        if ($pem === false) {
            throw new \LogicException(\sprintf('No test key "%s"', $name));
        }

        return self::fromPem($pem);
    }

    public static function rsa(int $bits = 2048, string $label = ''): self
    {
        return self::$generated['rsa-' . $bits . '-' . $label] ??= self::fromPem(Phpseclib::string(RSA::createKey($bits)->toString('PKCS8')));
    }

    public static function ec(string $curve = 'secp256r1', string $label = ''): self
    {
        return self::$generated['ec-' . $curve . '-' . $label] ??= self::fromPem(Phpseclib::string(EC::createKey($curve)->toString('PKCS8')));
    }

    public function publicKey(): PublicKey
    {
        return $this->privateKey->publicKey();
    }

    private static function fromPem(string $pem): self
    {
        $raw = PublicKeyLoader::loadPrivateKey($pem);
        if (!$raw instanceof RSA\PrivateKey && !$raw instanceof EC\PrivateKey) {
            throw new \LogicException('The test key is neither RSA nor EC');
        }

        return new self(PrivateKey::fromPem($pem), $raw);
    }
}
