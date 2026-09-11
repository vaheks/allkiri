<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Crypto;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\CertificateException;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\KeyType;
use Allkiri\Tests\Support\Pki\TestPki;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Certificate::class)]
final class CertificateTest extends TestCase
{
    private const CERTS = __DIR__ . '/../../fixtures/certs/';

    public function testEncodingsRoundTrip(): void
    {
        $cert = TestPki::signerEc256()->certificate;

        self::assertTrue(Certificate::fromPem($cert->pem())->equals($cert));
        self::assertTrue(Certificate::fromBase64(chunk_split($cert->base64(), 60))->equals($cert));
        self::assertTrue(Certificate::fromDer($cert->der())->equals($cert));
        self::assertSame(hash('sha256', $cert->der(), true), $cert->fingerprint(HashAlgorithm::SHA256));
    }

    public function testSubjectAndValidityOfTheTestSigner(): void
    {
        $cert = TestPki::signerEc256()->certificate;

        self::assertSame('ALLKIRI,TESTER,38001085718', $cert->commonName());
        self::assertSame('ALLKIRI', $cert->subjectAttribute('SN'));
        self::assertSame('TESTER', $cert->subjectAttribute('GN'));
        self::assertSame('PNOEE-38001085718', $cert->subjectAttribute('serialNumber'));
        self::assertSame('EE', $cert->subjectAttribute('C'));
        self::assertNull($cert->subjectAttribute('O'));
        self::assertStringContainsString('allkiri Test CA', $cert->issuerDn());
        self::assertSame('1001', $cert->serialNumber());
        self::assertSame('2020-01-01T00:00:00+00:00', $cert->notBefore()->format(DATE_ATOM));
        self::assertSame('2050-01-01T00:00:00+00:00', $cert->notAfter()->format(DATE_ATOM));
        self::assertTrue($cert->isValidAt(new \DateTimeImmutable('2026-09-11T00:00:00Z')));
        self::assertFalse($cert->isValidAt(new \DateTimeImmutable('2019-12-31T23:59:59Z')));
        self::assertFalse($cert->isValidAt(new \DateTimeImmutable('2050-01-01T00:00:01Z')));
    }

    public function testKeysAndExtensions(): void
    {
        $ca = TestPki::ca()->certificate;
        $ec = TestPki::signerEc256()->certificate;
        $rsa = TestPki::signerRsa()->certificate;
        $tsa = TestPki::tsa()->certificate;
        $ocsp = TestPki::ocspResponder()->certificate;

        self::assertSame(KeyType::EC, $ec->keyType());
        self::assertSame(256, $ec->keyBits());
        self::assertSame(32, \Allkiri\Crypto\EcdsaSignature::fieldBytesForCurve((string) $ec->curveName()));
        self::assertSame(KeyType::RSA, $rsa->keyType());
        self::assertSame(2048, $rsa->keyBits());
        self::assertNull($rsa->curveName());
        self::assertSame(65, \strlen($ec->subjectPublicKeyBytes()), 'uncompressed P-256 point');
        self::assertSame("\x30", $ec->subjectPublicKeyInfoDer()[0]);

        self::assertTrue($ca->isCa());
        self::assertFalse($ec->isCa());
        self::assertContains('keyCertSign', $ca->keyUsage());
        self::assertEqualsCanonicalizing(['digitalSignature', 'nonRepudiation'], $ec->keyUsage());
        self::assertSame(['1.3.6.1.5.5.7.3.8'], $tsa->extendedKeyUsage());
        self::assertTrue($tsa->hasExtendedKeyUsage('id-kp-timeStamping'));
        self::assertTrue($ocsp->hasExtendedKeyUsage('1.3.6.1.5.5.7.3.9'));
        self::assertFalse($ec->hasExtendedKeyUsage('id-kp-timeStamping'));
        self::assertFalse($ocsp->hasExtension(Certificate::OID_OCSP_NOCHECK));
        self::assertTrue($ec->hasExtension('id-pe-authorityInfoAccess'));

        self::assertSame(['http://ocsp.allkiri.test/'], $ec->ocspUrls());
        self::assertSame(['http://ca.allkiri.test/ca.crt'], $ec->caIssuersUrls());
        self::assertSame([], $ca->ocspUrls());

        self::assertNotNull($ca->subjectKeyIdentifier());
        self::assertSame($ca->subjectKeyIdentifier(), $ec->authorityKeyIdentifier());
        self::assertNull($ca->authorityKeyIdentifier());
    }

    public function testChainRelations(): void
    {
        $ca = TestPki::ca()->certificate;
        $ec = TestPki::signerEc256()->certificate;
        $rsa = TestPki::signerRsa()->certificate;

        self::assertTrue($ec->isSignedBy($ca));
        self::assertTrue($rsa->isSignedBy($ca));
        self::assertFalse($ec->isSignedBy($rsa));
        self::assertTrue($ca->isSelfSigned());
        self::assertFalse($ec->isSelfSigned());
        self::assertSame($ca->subjectNameDer(), $ec->issuerNameDer());
        self::assertNotSame($ec->subjectNameDer(), $ec->issuerNameDer());
        self::assertSame('1.2.840.113549.1.1.11', $ec->signatureAlgorithmOid(), 'sha256WithRSAEncryption, signed by the RSA CA');
    }

    public function testRealTestCaCertificatesFromSkAndZetes(): void
    {
        $root = Certificate::fromPem((string) file_get_contents(self::CERTS . 'TEST_of_SK_ID_Solutions_ROOT_G1E.pem'));
        $govCa = Certificate::fromPem((string) file_get_contents(self::CERTS . 'TEST_of_EE_GovCA2018.pem'));
        $esteid = Certificate::fromPem((string) file_get_contents(self::CERTS . 'TEST_of_ESTEID2018.pem'));
        $zetesRoot = Certificate::fromPem((string) file_get_contents(self::CERTS . 'testEEGovCA2025.pem'));
        $zetesCa = Certificate::fromPem((string) file_get_contents(self::CERTS . 'testESTEID2025.pem'));

        self::assertSame('TEST of ESTEID2018', $esteid->commonName());
        self::assertSame('NTREE-10747013', $esteid->subjectAttribute('organizationIdentifier'));
        self::assertTrue($esteid->isCa());
        self::assertTrue($esteid->isSignedBy($govCa));
        self::assertTrue($govCa->isSelfSigned(), 'EE-GovCA2018 is a root of its own, not under ROOT G1E');
        self::assertFalse($govCa->isSignedBy($root));
        self::assertTrue($root->isSelfSigned());
        self::assertFalse($esteid->isSignedBy($root));
        self::assertSame('1.2.840.10045.4.3.4', $esteid->signatureAlgorithmOid(), 'ecdsa-with-SHA512');

        self::assertSame('Test ESTEID2025', $zetesCa->commonName());
        self::assertSame('NTREE-17066049', $zetesCa->subjectAttribute('organizationIdentifier'));
        self::assertTrue($zetesCa->isSignedBy($zetesRoot));
        self::assertTrue($zetesRoot->isSelfSigned());
        self::assertSame($zetesRoot->subjectKeyIdentifier(), $zetesCa->authorityKeyIdentifier());
    }

    public function testGarbageIsRejected(): void
    {
        try {
            Certificate::fromPem('no pem here');
            self::fail('accepted text without a PEM block');
        } catch (CertificateException) {
        }

        $this->expectException(CertificateException::class);
        Certificate::fromDer("\x30\x03\x02\x01\x00");
    }
}
