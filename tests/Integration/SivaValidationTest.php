<?php

declare(strict_types=1);

namespace Allkiri\Tests\Integration;

use Allkiri\Allkiri;
use Allkiri\Clock\SystemClock;
use Allkiri\Config\Environment;
use Allkiri\Container\AsicContainer;
use Allkiri\Container\DataFile;
use Allkiri\Crypto\PrivateKey;
use Allkiri\Http\CurlHttpClient;
use Allkiri\Signing\LocalKeySigner;
use Allkiri\Signing\SignatureLevel;
use Allkiri\Tests\Support\Pki\TestPki;
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
     * Anything SiVa says about the format rather than the trust chain.
     */
    private const FORMAT_PROBLEMS = [
        'hash', 'digest', 'not intact', 'reference', 'mimetype', 'manifest',
        'DataObjectFormat', 'SignedProperties', 'canonical', 'malformed',
        'signature is not', 'unsupported',
    ];

    public function testAContainerWeSignIsFormallyAcceptableToSiva(): void
    {
        $environment = Environment::demo();
        $http = self::http(60);
        $allkiri = new Allkiri($environment, $http, new SystemClock());

        // Our test signer's certificate is not in SK's demo OCSP database, so
        // reach the real TSA but keep the OCSP answer from the demo responder
        // by uploading the certificate first; when that has not been done, the
        // signature cannot be completed and the test says so.
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

        $report = $this->siva($http, $environment)->validate($bytes, 'allkiri.asice');

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
            self::markTestSkipped('Set ALLKIRI_TEST_P12 to a PKCS#12 file whose CA is in the Estonian test trusted list (an SK test e-seal) to run the full interop gate.');
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

        $report = $this->siva($http, $environment)->validate($bytes, 'allkiri.asice');

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

        $report = $this->siva($http, $environment)->validate((string) file_get_contents($file), basename($file));

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

    private function siva(CurlHttpClient $http, Environment $environment): SivaClient
    {
        return new SivaClient($http, (string) $environment->sivaUrl);
    }

    private function assertNoFormatProblems(SivaReport $report): void
    {
        foreach ($report->allErrors() as $error) {
            foreach (self::FORMAT_PROBLEMS as $needle) {
                self::assertStringNotContainsStringIgnoringCase(
                    $needle,
                    $error,
                    'SiVa found something wrong with the format allkiri produced: ' . $error,
                );
            }
        }
    }
}
