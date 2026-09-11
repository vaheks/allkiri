<?php

declare(strict_types=1);

namespace Allkiri\Crypto;

use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\Exception\NoKeyLoadedException;

/**
 * A local signing key (e-seal, test key). Produces signature values in the
 * wire format allkiri uses everywhere: PKCS#1 / PSS bytes for RSA, raw r‖s
 * for ECDSA.
 */
final class PrivateKey
{
    private function __construct(private readonly RSA\PrivateKey|EC\PrivateKey $key) {}

    /**
     * @param string      $pem      PKCS#8 or traditional PEM (RSA or EC)
     * @param string|null $password for encrypted keys
     */
    public static function fromPem(string $pem, ?string $password = null): self
    {
        try {
            $key = $password === null ? PublicKeyLoader::loadPrivateKey($pem) : PublicKeyLoader::loadPrivateKey($pem, $password);
        } catch (NoKeyLoadedException $e) {
            throw new CryptoException('Not a supported private key: ' . $e->getMessage(), 0, $e);
        }
        if (!$key instanceof RSA\PrivateKey && !$key instanceof EC\PrivateKey) {
            throw new UnsupportedAlgorithmException(\sprintf('Unsupported private key type %s', get_debug_type($key)));
        }

        return new self($key);
    }

    /**
     * Load a PKCS#12 bundle (.p12 / .pfx) as issued for e-seals and test keys.
     */
    public static function fromPkcs12(string $pkcs12, string $password): KeyPair
    {
        $parts = null;
        if (!openssl_pkcs12_read($pkcs12, $parts, $password) || !\is_array($parts)) {
            throw new CryptoException('Could not read the PKCS#12 bundle (wrong password or unsupported encryption): ' . (string) openssl_error_string());
        }
        /** @var array<string, mixed> $parts */
        $keyPem = $parts['pkey'] ?? null;
        $certPem = $parts['cert'] ?? null;
        if (!\is_string($keyPem) || !\is_string($certPem)) {
            throw new CryptoException('The PKCS#12 bundle has no private key and certificate pair');
        }
        $chain = [];
        $extra = $parts['extracerts'] ?? [];
        if (\is_array($extra)) {
            foreach ($extra as $pem) {
                if (\is_string($pem)) {
                    $chain[] = Certificate::fromPem($pem);
                }
            }
        }

        return new KeyPair(self::fromPem($keyPem), Certificate::fromPem($certPem), $chain);
    }

    public function publicKey(): PublicKey
    {
        $public = $this->key->getPublicKey();
        if (!$public instanceof PublicKey) {
            throw new CryptoException('phpseclib returned no public key for the private key');
        }

        return $public;
    }

    public function keyType(): KeyType
    {
        return $this->key instanceof EC\PrivateKey ? KeyType::EC : KeyType::RSA;
    }

    /**
     * The algorithm allkiri would pick for this key ({@see SignatureAlgorithm::forKey}).
     */
    public function defaultAlgorithm(bool $preferPss = false): SignatureAlgorithm
    {
        return SignatureAlgorithm::forKey($this->publicKey(), $preferPss);
    }

    /**
     * Sign the data (not a digest) and return the wire-format signature value.
     */
    public function sign(SignatureAlgorithm $algorithm, string $data): string
    {
        if ($algorithm->keyType() !== $this->keyType()) {
            throw new CryptoException(\sprintf('%s needs a %s key', $algorithm->value, $algorithm->keyType()->name));
        }
        $hashName = $algorithm->hash()->value;
        if ($this->key instanceof EC\PrivateKey) {
            $key = Phpseclib::ecPrivate($this->key->withSignatureFormat('IEEE'));
            $key = Phpseclib::ecPrivate($key->withHash($hashName));

            return Phpseclib::string($key->sign($data));
        }
        $key = Phpseclib::rsaPrivate($this->key->withHash($hashName));
        if ($algorithm->isPss()) {
            $key = Phpseclib::rsaPrivate($key->withPadding(RSA::SIGNATURE_PSS));
            $key = Phpseclib::rsaPrivate($key->withMGFHash($hashName));
            $key = Phpseclib::rsaPrivate($key->withSaltLength($algorithm->hash()->digestLength()));
        } else {
            $key = Phpseclib::rsaPrivate($key->withPadding(RSA::SIGNATURE_PKCS1));
        }

        return Phpseclib::string($key->sign($data));
    }
}
