<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Validation;

use Allkiri\Container\AsicContainer;
use Allkiri\Container\AsicWriter;
use Allkiri\Container\DataFile;
use Allkiri\Container\Manifest;
use Allkiri\Container\Zip\ZipWriter;
use Allkiri\Signing\LocalKeySigner;
use Allkiri\Signing\SignatureLevel;
use Allkiri\Signing\SigningOptions;
use Allkiri\Tests\Support\Clock\FrozenClock;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Tests\Support\SigningFixture;
use Allkiri\Trust\InMemoryTrustStore;
use Allkiri\Trust\ServiceType;
use Allkiri\Validation\ContainerValidator;
use Allkiri\Validation\FindingCodes;
use Allkiri\Validation\Report\Indication;
use Allkiri\Validation\Report\SubIndication;
use Allkiri\Validation\SignatureValidator;
use Allkiri\Validation\ValidationOptions;
use Allkiri\Validation\ValidationPolicy;
use Allkiri\Xades\Ns;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class ValidationTest extends TestCase
{
    private const CONTAINERS = __DIR__ . '/../../fixtures/containers/';

    private static function validator(SigningFixture $fixture, ?ValidationPolicy $policy = null): ContainerValidator
    {
        $policy ??= new ValidationPolicy();

        return new ContainerValidator(
            new SignatureValidator($fixture->trustStore, $policy),
            $fixture->clock,
            $policy,
        );
    }

    /**
     * @return iterable<string, array{\Allkiri\Crypto\KeyPair}>
     */
    public static function signers(): iterable
    {
        yield 'ECDSA P-256' => [TestPki::signerEc256()];
        yield 'ECDSA P-384' => [TestPki::signerEc384()];
        yield 'RSA' => [TestPki::signerRsa()];
    }

    #[DataProvider('signers')]
    public function testOurOwnLtSignaturesValidate(\Allkiri\Crypto\KeyPair $keyPair): void
    {
        $fixture = new SigningFixture();
        $result = $fixture->signingService->signWith(
            AsicContainer::create(DataFile::fromString('leping.txt', "Tere!\n")),
            LocalKeySigner::fromKeyPair($keyPair),
        );
        $bytes = (new AsicWriter())->write($result->container);

        $report = self::validator($fixture)->validate($bytes, 'leping.asice');

        self::assertTrue($report->isValid(), implode('; ', array_map(static fn($f): string => $f->code . ': ' . $f->message, $report->signatures[0]->errors())));
        self::assertSame(1, $report->signaturesCount());
        self::assertSame(1, $report->validSignaturesCount());
        self::assertSame([], $report->containerFindings);

        $signature = $report->signatures[0];
        self::assertSame(Indication::TotalPassed, $signature->indication);
        self::assertNull($signature->subIndication);
        self::assertSame(SignatureLevel::LT, $signature->format);
        self::assertSame([], $signature->errors());
        self::assertSame([], $signature->warnings());
        self::assertSame($keyPair->certificate->commonName(), $signature->signedBy());
        self::assertSame('2026-03-01T10:00:00+00:00', $signature->info->claimedSigningTime?->format(DATE_ATOM));
        self::assertSame('2026-03-01T10:00:00+00:00', $signature->info->bestSignatureTime?->format(DATE_ATOM));
        self::assertSame('2026-03-01T10:00:00+00:00', $signature->info->timestampCreationTime?->format(DATE_ATOM));
        self::assertSame('2026-03-01T10:00:00+00:00', $signature->info->ocspResponseCreationTime?->format(DATE_ATOM));
        self::assertNotNull($signature->info->timeAssertionMessageImprint);
        self::assertCount(1, $signature->scopes);
        self::assertSame('leping.txt', $signature->scopes[0]->name);
        self::assertSame('text/plain', $signature->scopes[0]->mimeType);

        // The report is JSON-serialisable, which is how applications will pass it on.
        $json = (string) json_encode($report);
        self::assertJson($json);
        self::assertStringContainsString('"indication":"TOTAL-PASSED"', $json);
        self::assertStringContainsString('"signatureFormat":"XAdES_BASELINE_LT"', $json);
        self::assertStringContainsString('"validSignaturesCount":1', $json);
        self::assertStringContainsString('"filename":"leping.asice"', $json);
    }

    public function testEveryTamperingIsCaughtWithTheRightVerdict(): void
    {
        $fixture = new SigningFixture();
        $result = $fixture->signingService->signWith(
            AsicContainer::create(DataFile::fromString('a.txt', 'original')),
            LocalKeySigner::fromKeyPair(TestPki::signerEc256()),
        );
        $original = (new AsicWriter())->write($result->container);
        $validator = self::validator($fixture);
        $signatureXml = (string) $result->container->signatureFile('META-INF/signatures0.xml')?->xml;

        // A changed data file.
        $changed = (new ZipWriter())
            ->addStored('mimetype', Ns::MIME_ASICE)
            ->addDeflated('a.txt', 'tampered')
            ->addDeflated('META-INF/manifest.xml', Manifest::forDataFiles([DataFile::fromString('a.txt', 'tampered')])->toXml())
            ->addDeflated('META-INF/signatures0.xml', $signatureXml)
            ->build();
        $report = $validator->validate($changed);
        self::assertSame(Indication::TotalFailed, $report->signatures[0]->indication);
        self::assertSame(SubIndication::HashFailure, $report->signatures[0]->subIndication);
        self::assertTrue($report->signatures[0]->has(FindingCodes::DATA_FILE_DIGEST_MISMATCH));

        // A changed signature value.
        $brokenXml = preg_replace('/(<ds:SignatureValue[^>]*>)[A-Za-z0-9+\/]/', '$1X', $signatureXml, 1);
        self::assertIsString($brokenXml);
        $broken = (new ZipWriter())
            ->addStored('mimetype', Ns::MIME_ASICE)
            ->addDeflated('a.txt', 'original')
            ->addDeflated('META-INF/manifest.xml', Manifest::forDataFiles([DataFile::fromString('a.txt', 'original')])->toXml())
            ->addDeflated('META-INF/signatures0.xml', $brokenXml)
            ->build();
        $report = $validator->validate($broken);
        self::assertSame(Indication::TotalFailed, $report->signatures[0]->indication);
        self::assertSame(SubIndication::SigCryptoFailure, $report->signatures[0]->subIndication);
        self::assertTrue($report->signatures[0]->has(FindingCodes::SIGNATURE_INVALID));

        // An extra, unsigned file smuggled into the container.
        $extra = (new ZipWriter())
            ->addStored('mimetype', Ns::MIME_ASICE)
            ->addDeflated('a.txt', 'original')
            ->addDeflated('evil.txt', 'never signed')
            ->addDeflated('META-INF/manifest.xml', Manifest::forDataFiles([DataFile::fromString('a.txt', 'original'), DataFile::fromString('evil.txt', 'never signed')])->toXml())
            ->addDeflated('META-INF/signatures0.xml', $signatureXml)
            ->build();
        $report = $validator->validate($extra);
        self::assertSame(Indication::TotalFailed, $report->signatures[0]->indication);
        self::assertTrue($report->signatures[0]->has(FindingCodes::UNSIGNED_DATA_FILE));

        // The untouched original still passes, so the tests above changed only what they meant to.
        self::assertTrue($validator->validate($original)->isValid());
    }

    public function testStructuralProblemsFailTheSignaturesInThem(): void
    {
        $fixture = new SigningFixture();
        $result = $fixture->signingService->signWith(
            AsicContainer::create(DataFile::fromString('a.txt', 'x')),
            LocalKeySigner::fromKeyPair(TestPki::signerEc256()),
        );
        $signatureXml = (string) $result->container->signatureFile('META-INF/signatures0.xml')?->xml;
        $validator = self::validator($fixture);

        // mimetype missing entirely.
        $noMimetype = (new ZipWriter())
            ->addDeflated('a.txt', 'x')
            ->addDeflated('META-INF/manifest.xml', Manifest::forDataFiles([DataFile::fromString('a.txt', 'x')])->toXml())
            ->addDeflated('META-INF/signatures0.xml', $signatureXml)
            ->build();
        $report = $validator->validate($noMimetype);
        self::assertFalse($report->isValid());
        self::assertSame(Indication::TotalFailed, $report->signatures[0]->indication);
        self::assertSame([FindingCodes::MIMETYPE_INVALID], array_map(static fn($f): string => $f->code, $report->containerFindings));

        // Not a ZIP at all.
        $report = $validator->validate('definitely not a container', 'rubbish.asice');
        self::assertSame(0, $report->signaturesCount());
        self::assertFalse($report->isValid());
        self::assertSame(FindingCodes::NOT_A_CONTAINER, $report->containerFindings[0]->code);

        // A signature file that is not XML.
        $badXml = (new ZipWriter())
            ->addStored('mimetype', Ns::MIME_ASICE)
            ->addDeflated('a.txt', 'x')
            ->addDeflated('META-INF/manifest.xml', Manifest::forDataFiles([DataFile::fromString('a.txt', 'x')])->toXml())
            ->addDeflated('META-INF/signatures0.xml', 'not xml at all')
            ->build();
        $report = $validator->validate($badXml);
        self::assertSame(Indication::TotalFailed, $report->signatures[0]->indication);
        self::assertTrue($report->signatures[0]->has(FindingCodes::SIGNATURE_FILE_MALFORMED));
    }

    public function testAnUntrustedSignerIsIndeterminateNotInvalid(): void
    {
        $fixture = new SigningFixture();
        $result = $fixture->signingService->signWith(
            AsicContainer::create(DataFile::fromString('a.txt', 'x')),
            LocalKeySigner::fromKeyPair(TestPki::signerEc256()),
        );
        $bytes = (new AsicWriter())->write($result->container);

        // A trust store that knows the TSA but not the signer's CA.
        $strangerStore = InMemoryTrustStore::fromCertificates([TestPki::tsa()->certificate], ServiceType::TsaQtst);
        $report = self::validator($fixture)->validate($bytes, 'a.asice', new ValidationOptions(trustStore: $strangerStore));

        $signature = $report->signatures[0];
        self::assertSame(Indication::Indeterminate, $signature->indication, 'an unknown CA is not proof of forgery');
        self::assertSame(SubIndication::NoCertificateChainFound, $signature->subIndication);
        self::assertTrue($signature->has(FindingCodes::CHAIN_NOT_FOUND));
        self::assertSame([], $signature->warnings());
        // The cryptography was still checked and is fine.
        self::assertFalse($signature->has(FindingCodes::SIGNATURE_INVALID));
        self::assertFalse($signature->has(FindingCodes::DATA_FILE_DIGEST_MISMATCH));
    }

    public function testARevokedCertificateFailsAndAnUnknownOneIsIndeterminate(): void
    {
        foreach ([
            ['revoke', Indication::TotalFailed, SubIndication::Revoked, FindingCodes::CERTIFICATE_REVOKED],
            ['unknown', Indication::Indeterminate, SubIndication::TryLater, FindingCodes::CERTIFICATE_STATUS_UNKNOWN],
        ] as [$how, $indication, $subIndication, $code]) {
            // Sign while the responder still says "good", then validate against
            // a container whose embedded response says otherwise.
            $fixture = new SigningFixture();
            $keyPair = TestPki::signerEc256();
            $result = $fixture->signingService->signWith(AsicContainer::create(DataFile::fromString('a.txt', 'x')), LocalKeySigner::fromKeyPair($keyPair));

            $after = new SigningFixture($fixture->clock);
            if ($how === 'revoke') {
                $after->ocsp->revoke($keyPair->certificate->serialNumber(), new \DateTimeImmutable('2026-02-01T00:00:00Z'));
            } else {
                $after->ocsp->unknown($keyPair->certificate->serialNumber());
            }
            $replacement = $after->ocsp->handle(\Allkiri\Http\HttpRequest::post(
                \Allkiri\Tests\Support\Pki\MockOcspResponder::URL,
                'application/ocsp-request',
                \Allkiri\Crypto\Ocsp\OcspRequest::build(\Allkiri\Crypto\Ocsp\CertId::for($keyPair->certificate, TestPki::ca()->certificate))->der,
            ))->body;

            $xml = (string) $result->container->signatureFile('META-INF/signatures0.xml')?->xml;
            $swapped = preg_replace('#(<xades:EncapsulatedOCSPValue[^>]*>)[^<]+#', '$1' . base64_encode($replacement), $xml, 1);
            self::assertIsString($swapped);
            $bytes = (new ZipWriter())
                ->addStored('mimetype', Ns::MIME_ASICE)
                ->addDeflated('a.txt', 'x')
                ->addDeflated('META-INF/manifest.xml', Manifest::forDataFiles([DataFile::fromString('a.txt', 'x')])->toXml())
                ->addDeflated('META-INF/signatures0.xml', $swapped)
                ->build();

            $report = self::validator($fixture)->validate($bytes);
            $signature = $report->signatures[0];
            self::assertSame($indication, $signature->indication, $how);
            self::assertSame($subIndication, $signature->subIndication, $how);
            self::assertTrue($signature->has($code), $how);
        }
    }

    public function testLevelsBAndTAreReportedAsWhatTheyAre(): void
    {
        $fixture = new SigningFixture();
        $container = AsicContainer::create(DataFile::fromString('a.txt', 'x'));
        $signer = LocalKeySigner::fromKeyPair(TestPki::signerEc256());
        $validator = self::validator($fixture);

        $b = $fixture->besOnlyService()->signWith($container, $signer, (new SigningOptions())->withLevel(SignatureLevel::B));
        $bReport = $validator->validate((new AsicWriter())->write($b->container))->signatures[0];
        self::assertSame(SignatureLevel::B, $bReport->format);
        self::assertSame(Indication::Indeterminate, $bReport->indication);
        self::assertSame(SubIndication::TryLater, $bReport->subIndication);
        self::assertTrue($bReport->has(FindingCodes::REVOCATION_MISSING));
        self::assertSame('2026-03-01T10:00:00+00:00', $bReport->info->bestSignatureTime?->format(DATE_ATOM), 'the claimed time is used when there is no timestamp');

        $t = $fixture->signingService->signWith($container, $signer, (new SigningOptions())->withLevel(SignatureLevel::T));
        $tReport = $validator->validate((new AsicWriter())->write($t->container))->signatures[0];
        self::assertSame(SignatureLevel::T, $tReport->format);
        self::assertSame(Indication::Indeterminate, $tReport->indication);
        self::assertTrue($tReport->has(FindingCodes::REVOCATION_MISSING));
        self::assertNotNull($tReport->info->timestampCreationTime);
    }

    public function testThePolicyDecidesWhatIsAcceptable(): void
    {
        $fixture = new SigningFixture();
        $result = $fixture->signingService->signWith(
            AsicContainer::create(DataFile::fromString('a.txt', 'x')),
            LocalKeySigner::fromKeyPair(TestPki::signerRsa()),
        );
        $bytes = (new AsicWriter())->write($result->container);

        self::assertTrue(self::validator($fixture)->validate($bytes)->isValid());

        // A policy that demands a bigger RSA key than the signer has.
        $strict = new ValidationPolicy(minimumRsaKeyBits: 4096);
        $report = self::validator($fixture, $strict)->validate($bytes);
        self::assertSame(Indication::TotalFailed, $report->signatures[0]->indication);
        self::assertSame(SubIndication::CryptoConstraintsFailure, $report->signatures[0]->subIndication);
        self::assertTrue($report->signatures[0]->has(FindingCodes::WEAK_KEY));

        // A policy that only accepts SHA-512 digests.
        $sha512Only = new ValidationPolicy(allowedDigestAlgorithms: [\Allkiri\Crypto\HashAlgorithm::SHA512]);
        $report = self::validator($fixture, $sha512Only)->validate($bytes);
        self::assertTrue($report->signatures[0]->has(FindingCodes::WEAK_DIGEST_ALGORITHM));
    }

    public function testALateOcspResponseWarnsAndAVeryLateOneFails(): void
    {
        foreach ([[16 * 60, false], [25 * 3600, true]] as [$offset, $shouldFail]) {
            $fixture = new SigningFixture();
            $fixture->tsa->genTimeOffsetSeconds = -$offset;
            $result = $fixture->signingService->signWith(
                AsicContainer::create(DataFile::fromString('a.txt', 'x')),
                LocalKeySigner::fromKeyPair(TestPki::signerEc256()),
            );
            $report = self::validator($fixture)->validate((new AsicWriter())->write($result->container));
            $signature = $report->signatures[0];

            if ($shouldFail) {
                self::assertSame(Indication::TotalFailed, $signature->indication);
                self::assertSame(SubIndication::TimestampOrderFailure, $signature->subIndication);
                self::assertTrue($signature->has(FindingCodes::OCSP_TIMESTAMP_DELTA_TOO_LARGE));
            } else {
                self::assertTrue($signature->isValid());
                self::assertTrue($signature->has(FindingCodes::OCSP_TIMESTAMP_DELTA_WARNING));
                self::assertCount(1, $signature->warnings());
            }
        }
    }

    public function testATwoSignatureContainerReportsBoth(): void
    {
        $fixture = new SigningFixture();
        $container = AsicContainer::create(DataFile::fromString('a.txt', 'x'));
        $first = $fixture->signingService->signWith($container, LocalKeySigner::fromKeyPair(TestPki::signerEc256()));
        $second = $fixture->signingService->signWith($first->container, LocalKeySigner::fromKeyPair(TestPki::signerRsa()));

        $report = self::validator($fixture)->validate((new AsicWriter())->write($second->container));

        self::assertSame(2, $report->signaturesCount());
        self::assertSame(2, $report->validSignaturesCount());
        self::assertTrue($report->isValid());
        $files = array_map(static fn($s): string => $s->signatureFileName, $report->signatures);
        self::assertSame(['META-INF/signatures0.xml', 'META-INF/signatures1.xml'], $files);
        self::assertNotNull($report->signature($report->signatures[0]->id));
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function digidoc4jContainers(): iterable
    {
        yield 'ECDSA P-384, ESTEID2018' => ['valid-asice-esteid2018.asice', 1];
        yield 'RSA, ESTEID-SK 2015' => ['valid-asice.asice', 1];
        yield 'LTA' => ['valid-asice-lta.asice', 1];
        yield 'OCSP 15m6s after the timestamp' => ['EE_LT_sig_OCSP_15m6s_after_TS.asice', 1];
        yield 'no CertificateValues' => ['NoAdditionalCertificates_LT.asice', 1];
        yield 'two signatures' => ['2_signatures_duplicate_id.asice', 2];
    }

    /**
     * Reverse interop: containers made by digidoc4j must not fail for reasons
     * of our own making. We have no trust anchors for SK's test PKI here, so
     * the chain is expectedly unknown; everything cryptographic must still check out.
     */
    #[DataProvider('digidoc4jContainers')]
    public function testDigidoc4jContainersAreNotRejectedForTheWrongReasons(string $file, int $expectedSignatures): void
    {
        $fixture = new SigningFixture(new FrozenClock('2026-09-11T00:00:00Z'));
        $report = self::validator($fixture)->validateFile(self::CONTAINERS . $file);

        self::assertSame($expectedSignatures, $report->signaturesCount());
        self::assertSame([], $report->containerFindings, 'the container structure itself is sound');

        foreach ($report->signatures as $signature) {
            $codes = $signature->codes();
            foreach ([
                FindingCodes::DATA_FILE_DIGEST_MISMATCH,
                FindingCodes::SIGNED_PROPERTIES_DIGEST_MISMATCH,
                FindingCodes::SIGNATURE_INVALID,
                FindingCodes::SIGNING_CERTIFICATE_DIGEST_MISMATCH,
                FindingCodes::UNSIGNED_DATA_FILE,
                FindingCodes::MISSING_DATA_OBJECT_FORMAT,
                FindingCodes::SIGNED_PROPERTIES_REFERENCE_MISSING,
                FindingCodes::ISSUER_SERIAL_MISMATCH,
                FindingCodes::WEAK_DIGEST_ALGORITHM,
                FindingCodes::WEAK_SIGNATURE_ALGORITHM,
                FindingCodes::WEAK_KEY,
                FindingCodes::UNSUPPORTED_CANONICALIZATION,
            ] as $mustNotAppear) {
                self::assertNotContains($mustNotAppear, $codes, $file . ' / ' . $signature->id);
            }

            // Everything that is missing is missing because we do not trust SK's test PKI here.
            self::assertSame(Indication::Indeterminate, $signature->indication, $file);
            self::assertContains($signature->subIndication, [SubIndication::NoPoe, SubIndication::NoCertificateChainFound], $file);
            self::assertNotNull($signature->signingCertificate, $file);
            self::assertNotNull($signature->signedBy(), $file);
            self::assertNotNull($signature->info->claimedSigningTime, $file);
            self::assertNotSame([], $signature->scopes, $file);
        }
    }

    public function testADigidoc4jContainerValidatesFullyWhenItsPkiIsTrusted(): void
    {
        $certs = __DIR__ . '/../../fixtures/certs/';
        $store = new \Allkiri\Trust\CompositeTrustStore(
            InMemoryTrustStore::fromCertificates([
                \Allkiri\Crypto\Certificate::fromPem((string) file_get_contents($certs . 'TEST_of_ESTEID2018.pem')),
            ], ServiceType::CaQc, 'EE_T'),
            InMemoryTrustStore::fromCertificates([
                // The demo TSA and the AIA OCSP responder that signed this container.
                ...self::embeddedCertificates(self::CONTAINERS . 'valid-asice-esteid2018.asice', 'TIMESTAMPING'),
            ], ServiceType::TsaQtst, 'EE_T'),
            InMemoryTrustStore::fromCertificates([
                ...self::embeddedCertificates(self::CONTAINERS . 'valid-asice-esteid2018.asice', 'OCSP RESPONDER'),
            ], ServiceType::OcspQc, 'EE_T'),
        );
        $fixture = new SigningFixture(new FrozenClock('2026-09-11T00:00:00Z'));
        $validator = new ContainerValidator(new SignatureValidator($store), $fixture->clock);

        $report = $validator->validateFile(self::CONTAINERS . 'valid-asice-esteid2018.asice');
        $signature = $report->signatures[0];

        self::assertTrue($report->isValid(), implode('; ', array_map(static fn($f): string => $f->code . ': ' . $f->message, $signature->errors())));
        self::assertSame(SignatureLevel::LT, $signature->format);
        self::assertStringContainsString('JÕEORG', (string) $signature->signedBy());
        self::assertSame('2024-09-02T12:36:44+00:00', $signature->info->claimedSigningTime?->format(DATE_ATOM));
        self::assertNotNull($signature->info->timestampCreationTime);
        self::assertNotNull($signature->info->ocspResponseCreationTime);
        self::assertSame('test.txt', $signature->scopes[0]->name);
    }

    /**
     * @return list<\Allkiri\Crypto\Certificate>
     */
    private static function embeddedCertificates(string $container, string $commonNameContains): array
    {
        $zip = new \ZipArchive();
        $zip->open($container);
        $xml = (string) $zip->getFromName('META-INF/signatures0.xml');
        $zip->close();

        $found = [];
        preg_match_all('#<xades:EncapsulatedX509Certificate[^>]*>([^<]+)#', $xml, $matches);
        foreach ($matches[1] as $base64) {
            $certificate = \Allkiri\Crypto\Certificate::fromBase64($base64);
            if (str_contains((string) $certificate->commonName(), $commonNameContains)) {
                $found[] = $certificate;
            }
        }

        return $found;
    }
}
