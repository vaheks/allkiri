<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Crypto;

use Allkiri\Crypto\KeyPair;
use Allkiri\Crypto\PublicKeyVerifier;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Crypto\UnsupportedAlgorithmException;
use Allkiri\Tests\Support\Pki\TestPki;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(PublicKeyVerifier::class)]
final class PublicKeyVerifierTest extends TestCase
{
    /**
     * @return iterable<string, array{SignatureAlgorithm, KeyPair}>
     */
    public static function algorithmMatrix(): iterable
    {
        yield 'RS256' => [SignatureAlgorithm::RS256, TestPki::signerRsa()];
        yield 'RS384' => [SignatureAlgorithm::RS384, TestPki::signerRsa()];
        yield 'RS512' => [SignatureAlgorithm::RS512, TestPki::signerRsa()];
        yield 'PS256' => [SignatureAlgorithm::PS256, TestPki::signerRsa()];
        yield 'PS384' => [SignatureAlgorithm::PS384, TestPki::signerRsa()];
        yield 'PS512' => [SignatureAlgorithm::PS512, TestPki::signerRsa()];
        yield 'ES256' => [SignatureAlgorithm::ES256, TestPki::signerEc256()];
        yield 'ES384' => [SignatureAlgorithm::ES384, TestPki::signerEc384()];
        yield 'ES512 on P-384' => [SignatureAlgorithm::ES512, TestPki::signerEc384()];
    }

    #[DataProvider('algorithmMatrix')]
    public function testSignThenVerify(SignatureAlgorithm $algorithm, KeyPair $pair): void
    {
        $verifier = new PublicKeyVerifier();
        $data = 'canonical SignedInfo bytes';
        $signature = $pair->privateKey->sign($algorithm, $data);

        self::assertTrue($verifier->verify($pair->certificate->publicKey(), $algorithm, $data, $signature));
        self::assertFalse($verifier->verify($pair->certificate->publicKey(), $algorithm, $data . '!', $signature), 'tampered data');
        $flipped = $signature;
        $flipped[5] = \chr(\ord($flipped[5]) ^ 0x01);
        self::assertFalse($verifier->verify($pair->certificate->publicKey(), $algorithm, $data, $flipped), 'tampered signature');
        self::assertFalse($verifier->verify($pair->certificate->publicKey(), $algorithm, $data, ''), 'empty signature');
    }

    public function testWrongKeyTypeOrLengthIsSimplyFalse(): void
    {
        $verifier = new PublicKeyVerifier();
        $ec = TestPki::signerEc256();
        $rsa = TestPki::signerRsa();
        $signature = $ec->privateKey->sign(SignatureAlgorithm::ES256, 'x');

        self::assertFalse($verifier->verify($rsa->certificate->publicKey(), SignatureAlgorithm::ES256, 'x', $signature));
        self::assertFalse($verifier->verify($ec->certificate->publicKey(), SignatureAlgorithm::RS256, 'x', $signature));
        self::assertFalse($verifier->verify($ec->certificate->publicKey(), SignatureAlgorithm::ES256, 'x', $signature . "\0"));
    }

    public function testVerifyWithOidCoversCertificateSignatures(): void
    {
        $verifier = new PublicKeyVerifier();
        $ca = TestPki::ca()->certificate;
        $leaf = TestPki::signerEc256()->certificate;

        self::assertTrue($verifier->verifyWithOid($ca->publicKey(), $leaf->signatureAlgorithmOid(), $leaf->tbsCertificateDer(), $leaf->signatureValue()));
        self::assertFalse($verifier->verifyWithOid($leaf->publicKey(), $leaf->signatureAlgorithmOid(), $leaf->tbsCertificateDer(), $leaf->signatureValue()));
        self::assertTrue($verifier->supportsOid('1.2.840.10045.4.3.2'));
        self::assertFalse($verifier->supportsOid('1.2.840.113549.1.1.10'));

        $this->expectException(UnsupportedAlgorithmException::class);
        $verifier->verifyWithOid($ca->publicKey(), '1.2.840.113549.1.1.10', 'x', 'y');
    }
}
