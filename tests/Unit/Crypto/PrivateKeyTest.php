<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Crypto;

use Allkiri\Crypto\CryptoException;
use Allkiri\Crypto\KeyPair;
use Allkiri\Crypto\KeyType;
use Allkiri\Crypto\PrivateKey;
use Allkiri\Crypto\PublicKeyVerifier;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Tests\Support\Pki\TestPki;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(PrivateKey::class)]
#[CoversClass(KeyPair::class)]
final class PrivateKeyTest extends TestCase
{
    public function testDefaultsAndSignatureLengths(): void
    {
        $ec = TestPki::signerEc256()->privateKey;
        $ec384 = TestPki::signerEc384()->privateKey;
        $rsa = TestPki::signerRsa()->privateKey;

        self::assertSame(KeyType::EC, $ec->keyType());
        self::assertSame(SignatureAlgorithm::ES256, $ec->defaultAlgorithm());
        self::assertSame(SignatureAlgorithm::ES384, $ec384->defaultAlgorithm());
        self::assertSame(SignatureAlgorithm::RS256, $rsa->defaultAlgorithm());
        self::assertSame(SignatureAlgorithm::PS256, $rsa->defaultAlgorithm(preferPss: true));

        self::assertSame(64, \strlen($ec->sign(SignatureAlgorithm::ES256, 'data')));
        self::assertSame(96, \strlen($ec384->sign(SignatureAlgorithm::ES384, 'data')));
        self::assertSame(256, \strlen($rsa->sign(SignatureAlgorithm::RS256, 'data')));
        self::assertSame(256, \strlen($rsa->sign(SignatureAlgorithm::PS256, 'data')));
    }

    public function testAlgorithmMustMatchKeyType(): void
    {
        $this->expectException(CryptoException::class);
        TestPki::signerEc256()->privateKey->sign(SignatureAlgorithm::RS256, 'data');
    }

    public function testGarbagePemIsRejected(): void
    {
        $this->expectException(CryptoException::class);
        PrivateKey::fromPem('-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----');
    }

    public function testPkcs12RoundTrip(): void
    {
        $pair = TestPki::signerRsa();
        $keyPem = (string) file_get_contents(TestPki::DIR . '/signer-rsa.key.pem');
        $bundle = '';
        self::assertTrue(openssl_pkcs12_export($pair->certificate->pem(), $bundle, $keyPem, 'secret', ['extracerts' => [TestPki::ca()->certificate->pem()]]));
        self::assertIsString($bundle);

        $loaded = PrivateKey::fromPkcs12($bundle, 'secret');

        self::assertTrue($loaded->certificate->equals($pair->certificate));
        self::assertCount(1, $loaded->chain);
        self::assertTrue($loaded->chain[0]->equals(TestPki::ca()->certificate));
        $signature = $loaded->privateKey->sign(SignatureAlgorithm::RS256, 'x');
        self::assertTrue((new PublicKeyVerifier())->verify($pair->certificate->publicKey(), SignatureAlgorithm::RS256, 'x', $signature));

        $this->expectException(CryptoException::class);
        PrivateKey::fromPkcs12($bundle, 'wrong');
    }
}
