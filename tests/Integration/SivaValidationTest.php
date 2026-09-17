<?php

declare(strict_types=1);

namespace Allkiri\Tests\Integration;

use Allkiri\Allkiri;
use Allkiri\Clock\SystemClock;
use Allkiri\Config\Environment;
use Allkiri\Container\AsicContainer;
use Allkiri\Container\DataFile;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\Ocsp\CertId;
use Allkiri\Crypto\Ocsp\OcspRequest;
use Allkiri\Crypto\Ocsp\OcspResponse;
use Allkiri\Crypto\PrivateKey;
use Allkiri\Http\CurlHttpClient;
use Allkiri\Http\HttpRequest;
use Allkiri\Signing\LocalKeySigner;
use Allkiri\Signing\SignatureLevel;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustAnchor;
use Allkiri\Validation\Report\Indication;
use Allkiri\Validation\Siva\SivaClient;
use Allkiri\Validation\Siva\SivaReport;

/**
 * The interop gate: containers allkiri produces, judged by RIA's own service.
 *
 * Two tiers, because a signature's trust depends on a certificate we may not
 * have. Tier A signs with our own test CA, which SiVa cannot trust, so it
 * checks that SiVa finds nothing wrong with the *format*. Tier B needs a key
 * whose CA is in the Estonian test trusted list (an SK test e-seal, supplied
 * through ALLKIRI_TEST_P12) and expects a clean TOTAL-PASSED.
 */
final class SivaValidationTest extends IntegrationTestCase
{
    /**
     * The only complaints SiVa may make about a container signed with our own
     * test CA: it has no reason to trust that CA. Anything else means we
     * produced something malformed, which is what this test is looking for.
     */
    private const EXPECTED_TRUST_COMPLAINTS = [
        'trust anchor',
        'not trusted',
        'is not qualified',
        'QC',
        'trusted list',
    ];

    public function testAContainerWeSignIsFormallyAcceptableToSiva(): void
    {
        $http = self::http(60);
        $environment = $this->demoEnvironmentForOurTestKey($http);
        $allkiri = new Allkiri($environment, $http, new SystemClock());

        $container = AsicContainer::create(DataFile::fromString('allkiri.txt', 'SiVa interop check ' . date(DATE_ATOM)));
        try {
            $result = $allkiri->signingService()->signWith($container, LocalKeySigner::fromKeyPair(TestPki::signerRsa()));
        } catch (\Allkiri\Signing\SigningException $e) {
            self::markTestSkipped(
                'Could not complete an LT signature with the test key: ' . $e->getMessage()
                . '. Upload tests/fixtures/pki/signer-rsa.cert.pem at https://demo.sk.ee/upload_cert/ (status "Good") to enable this test.',
            );
        }

        self::assertSame(SignatureLevel::LT, $result->level);
        $bytes = $allkiri->writer()->write($result->container);

        $report = self::askSiva($this->siva($http, $environment), $bytes, 'allkiri.asice');

        self::assertSame(1, $report->signaturesCount);
        $signature = $report->signatures[0];
        self::assertSame('XAdES_BASELINE_LT', $signature->signatureFormat, 'SiVa recognises the level we claim');
        $this->assertNoFormatProblems($report);

        // Our own validator must agree about the parts SiVa can see.
        $ours = $allkiri->validator()->validate($bytes, 'allkiri.asice')->signatures[0];
        self::assertSame(SignatureLevel::LT, $ours->format);
        if ($signature->isValid()) {
            self::assertSame(Indication::TotalPassed, $ours->indication, 'SiVa accepted a signature we do not');
        }
    }

    public function testATrustedKeyProducesACleanTotalPassed(): void
    {
        $bundle = getenv('ALLKIRI_TEST_P12');
        if (!\is_string($bundle) || $bundle === '' || !is_file($bundle)) {
            self::markTestSkipped('Set ALLKIRI_TEST_P12 to a PKCS#12 file whose CA is in the Estonian test trusted list (an SK test e-seal) to run the local-key form of this gate. The gate itself is already met by MobileIdDemoTest, which signs with a demo Mobile-ID whose CA the test trusted list carries.');
        }
        $password = getenv('ALLKIRI_TEST_P12_PASSWORD');
        $keyPair = PrivateKey::fromPkcs12((string) file_get_contents($bundle), \is_string($password) ? $password : '');

        $environment = Environment::demo();
        $http = self::http(60);
        $allkiri = new Allkiri($environment, $http, new SystemClock());

        $result = $allkiri->signingService()->signWith(
            AsicContainer::create(DataFile::fromString('allkiri.txt', 'SiVa interop check ' . date(DATE_ATOM))),
            new LocalKeySigner(...[$keyPair->privateKey, $keyPair->certificate]),
        );
        $bytes = $allkiri->writer()->write($result->container);

        $report = self::askSiva($this->siva($http, $environment), $bytes, 'allkiri.asice');

        self::assertTrue($report->isValid(), 'SiVa rejected the signature: ' . implode('; ', $report->allErrors()));
        self::assertSame('XAdES_BASELINE_LT', $report->signatures[0]->signatureFormat);
        self::assertSame('ASiC-E', $report->signatureForm);

        // And our own verdict matches.
        $ours = $allkiri->validator()->validate($bytes, 'allkiri.asice');
        self::assertTrue($ours->isValid(), 'we rejected a signature SiVa accepted: ' . implode('; ', array_map(static fn($f): string => $f->message, $ours->signatures[0]->errors())));
    }

    public function testSivaAgreesWithUsAboutADigidoc4jContainer(): void
    {
        $environment = Environment::demo();
        $http = self::http(60);
        $file = __DIR__ . '/../fixtures/containers/valid-asice-esteid2018.asice';

        $report = self::askSiva($this->siva($http, $environment), (string) file_get_contents($file), basename($file));

        self::assertTrue($report->isValid(), 'SiVa rejected a digidoc4j container: ' . implode('; ', $report->allErrors()));
        self::assertSame('XAdES_BASELINE_LT', $report->signatures[0]->signatureFormat);
        self::assertStringContainsString('JÕEORG', (string) $report->signatures[0]->signedBy);

        // We reach the same verdict once the same PKI is trusted, which the
        // unit suite proves; here we only check we see the same shape.
        $allkiri = new Allkiri($environment, $http, new SystemClock());
        $ours = $allkiri->validator()->validateFile($file)->signatures[0];
        self::assertSame(SignatureLevel::LT, $ours->format);
        self::assertSame($report->signatures[0]->signedBy, $ours->signedBy());
        self::assertSame($report->signatures[0]->claimedSigningTime, $ours->info->claimedSigningTime?->format('Y-m-d\TH:i:s\Z'));
    }

    /**
     * The demo environment adjusted so our own test key can be used with it.
     *
     * Two things have to be arranged, both peculiar to the demo upload service
     * rather than to how signing normally works:
     *
     * 1. Our test certificate names a responder that does not exist
     *    (`http://ocsp.allkiri.test/`), so the demo responder is configured for
     *    its issuer instead. A real certificate names a real responder.
     * 2. demo.sk.ee/ocsp answers for uploaded certificates with one shared
     *    responder, which our test CA did not issue. RFC 6960 therefore does
     *    not authorise it, and allkiri refuses it unless it is named as a
     *    trusted responder. That is what a "Trusted Responder" is for, and the
     *    certificate is taken from a probe response because SK rotates it.
     */
    private function demoEnvironmentForOurTestKey(CurlHttpClient $http): Environment
    {
        $environment = Environment::demo();
        $issuer = TestPki::ca()->certificate;
        $ocspUrl = (string) $environment->ocspDefaultUrl;

        $request = OcspRequest::build(CertId::for(TestPki::signerRsa()->certificate, $issuer));
        $response = $http->send(HttpRequest::post($ocspUrl, 'application/ocsp-request', $request->der));
        if (!$response->isSuccess()) {
            self::markTestSkipped(\sprintf('%s answered HTTP %d', $ocspUrl, $response->status));
        }
        $responders = OcspResponse::fromDer($response->body)->basic()?->certificates() ?? [];
        if ($responders === []) {
            self::markTestSkipped('The demo responder sent no certificate, so it cannot be named as a trusted responder');
        }

        return $environment
            ->withOcspUrlOverrides([$issuer->subjectDn() => $ocspUrl])
            ->withExtraTrustAnchors([
                ...$environment->extraTrustAnchors,
                TrustAnchor::manual($issuer, ServiceType::CaQc, 'allkiri test CA'),
                ...array_map(
                    static fn(Certificate $c): TrustAnchor => TrustAnchor::manual($c, ServiceType::OcspQc, (string) $c->commonName(), 'demo.sk.ee probe'),
                    $responders,
                ),
            ]);
    }

    private function siva(CurlHttpClient $http, Environment $environment): SivaClient
    {
        return new SivaClient($http, (string) $environment->sivaUrl);
    }

    private function assertNoFormatProblems(SivaReport $report): void
    {
        foreach ($report->allErrors() as $error) {
            $expected = false;
            foreach (self::EXPECTED_TRUST_COMPLAINTS as $needle) {
                if (stripos($error, $needle) !== false) {
                    $expected = true;
                    break;
                }
            }
            self::assertTrue($expected, 'SiVa found something wrong with the format allkiri produced: ' . $error);
        }
    }
}
