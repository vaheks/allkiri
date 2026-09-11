<?php

declare(strict_types=1);

namespace Allkiri\Tests\Integration;

use Allkiri\Clock\SystemClock;
use Allkiri\Config\Environment;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\Ocsp\CertificateRevokedException;
use Allkiri\Crypto\Ocsp\CertStatus;
use Allkiri\Crypto\Ocsp\OcspClient;
use Allkiri\Crypto\Ocsp\OcspException;
use Allkiri\Crypto\Ocsp\OcspVerificationOptions;

/**
 * SK's demo validity confirmation service, against a real test certificate.
 */
final class DemoOcspTest extends IntegrationTestCase
{
    private const CERTS = __DIR__ . '/../fixtures/certs/';

    public function testTheDemoResponderAnswersForAnEsteid2018TestCertificate(): void
    {
        $subject = Certificate::fromPem((string) file_get_contents(self::CERTS . 'TEST_ESTEID2018_signer_JOEORG.pem'));
        $issuer = Certificate::fromPem((string) file_get_contents(self::CERTS . 'TEST_of_ESTEID2018.pem'));
        $client = new OcspClient(
            self::http(20),
            new SystemClock(),
            options: OcspVerificationOptions::forSigning(),
            defaultUrl: Environment::demo()->ocspDefaultUrl,
        );

        // The certificate names its own responder, which is the free AIA one.
        self::assertSame('http://aia.demo.sk.ee/esteid2018', $client->responderUrl($subject, $issuer));

        $result = $client->fetch($subject, $issuer);

        self::assertSame(CertStatus::Good, $result->verification->status());
        self::assertStringContainsString('OCSP RESPONDER', (string) $result->verification->responder->commonName());
        self::assertFalse($result->verification->responderIsIssuer, 'SK delegates to a responder the CA issued');
        self::assertTrue($result->verification->responder->hasExtendedKeyUsage('id-kp-OCSPSigning'));
        self::assertLessThan(300, abs($result->verification->producedAt()->getTimestamp() - time()));
        self::assertSame($result->der(), \Allkiri\Crypto\Ocsp\OcspResponse::fromDer($result->der())->der());
    }

    public function testTheCommercialDemoEndpointAnswersTheSameQuestion(): void
    {
        $subject = Certificate::fromPem((string) file_get_contents(self::CERTS . 'TEST_ESTEID2018_signer_JOEORG.pem'));
        $issuer = Certificate::fromPem((string) file_get_contents(self::CERTS . 'TEST_of_ESTEID2018.pem'));
        $ca = $issuer->subjectDn();
        $client = new OcspClient(
            self::http(20),
            new SystemClock(),
            options: OcspVerificationOptions::forSigning(),
            urlOverrides: [$ca => (string) Environment::demo()->ocspDefaultUrl],
        );

        try {
            $result = $client->fetch($subject, $issuer);
        } catch (OcspException $e) {
            self::markTestSkipped('demo.sk.ee/ocsp did not answer: ' . $e->getMessage());
        }

        self::assertSame(CertStatus::Good, $result->verification->status());
        self::assertSame((string) Environment::demo()->ocspDefaultUrl, $result->url);
    }

    public function testAnUnknownCertificateIsReportedAsSuch(): void
    {
        // Our own test CA is unknown to SK, so its certificates are too.
        $subject = \Allkiri\Tests\Support\Pki\TestPki::signerRsa()->certificate;
        $issuer = \Allkiri\Tests\Support\Pki\TestPki::ca()->certificate;
        $client = new OcspClient(
            self::http(20),
            new SystemClock(),
            options: OcspVerificationOptions::forSigning(),
            urlOverrides: [$issuer->subjectDn() => (string) Environment::demo()->ocspDefaultUrl],
        );

        try {
            $client->fetch($subject, $issuer);
            self::fail('the demo responder claimed to know a certificate from our own test CA');
        } catch (CertificateRevokedException $e) {
            // Either answer is fine: it does not know the certificate, or it
            // treats anything not uploaded to demo.sk.ee/upload_cert as revoked.
            self::assertContains($e->reason, [CertificateRevokedException::REASON_UNKNOWN, CertificateRevokedException::REASON_REVOKED]);
        } catch (OcspException $e) {
            self::assertNotSame('', $e->reason, 'the responder refused the question: ' . $e->getMessage());
        }
    }
}
