<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Validation;

use Allkiri\Container\AsicContainer;
use Allkiri\Container\AsicWriter;
use Allkiri\Container\DataFile;
use Allkiri\Container\Manifest;
use Allkiri\Container\Zip\ZipReader;
use Allkiri\Container\Zip\ZipWriter;
use Allkiri\Crypto\Asn1\Asn1;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\KeyPair;
use Allkiri\Crypto\Ocsp\CertId;
use Allkiri\Crypto\Ocsp\OcspRequest;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Crypto\Tsp\TimestampRequest;
use Allkiri\Crypto\Tsp\TimestampResponse;
use Allkiri\Crypto\Tsp\TimestampToken;
use Allkiri\Http\HttpRequest;
use Allkiri\Signing\DataToBeSigned;
use Allkiri\Signing\LocalKeySigner;
use Allkiri\Signing\SignatureLevel;
use Allkiri\Signing\SigningOptions;
use Allkiri\Signing\SigningResult;
use Allkiri\Tests\Support\Clock\FrozenClock;
use Allkiri\Tests\Support\Crypto\DerPatch;
use Allkiri\Tests\Support\Pki\MockOcspResponder;
use Allkiri\Tests\Support\Pki\MockTsa;
use Allkiri\Tests\Support\Pki\TestCertificates;
use Allkiri\Tests\Support\Pki\TestCertificateSignature;
use Allkiri\Tests\Support\Pki\TestIssuer;
use Allkiri\Tests\Support\Pki\TestKey;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Tests\Support\Pki\TestSignatures;
use Allkiri\Tests\Support\SigningFixture;
use Allkiri\Tests\Support\Xades\SignatureWrapping;
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
use Allkiri\Xades\SignatureBuilder;
use phpseclib3\Math\BigInteger;
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
     * An OCSP answer for the certificate, as the fixture's responder would give it now.
     */
    private static function ocspAnswer(SigningFixture $fixture, Certificate $certificate): string
    {
        return $fixture->ocsp->handle(HttpRequest::post(
            MockOcspResponder::URL,
            'application/ocsp-request',
            OcspRequest::build(CertId::for($certificate, TestPki::ca()->certificate))->der,
        ))->body;
    }

    /**
     * The signed container of a.txt again, with one encapsulated value in its
     * signature replaced. Unsigned properties are not covered by the signature,
     * which is what makes the swap possible.
     *
     * @param string $element the xades element, such as EncapsulatedOCSPValue
     */
    private static function withEncapsulated(SigningResult $result, string $element, string $der): string
    {
        $xml = (string) $result->container->signatureFile('META-INF/signatures0.xml')?->xml;
        $swapped = preg_replace('#(<xades:' . $element . '[^>]*>)[^<]+#', '${1}' . base64_encode($der), $xml, 1);
        self::assertIsString($swapped);

        return self::containerOfA($swapped);
    }

    /**
     * The one-file container of a.txt, with the given signature file.
     */
    private static function containerOfA(string $signatureXml): string
    {
        return (new ZipWriter())
            ->addStored('mimetype', Ns::MIME_ASICE)
            ->addDeflated('a.txt', 'x')
            ->addDeflated('META-INF/manifest.xml', Manifest::forDataFiles([DataFile::fromString('a.txt', 'x')])->toXml())
            ->addDeflated('META-INF/signatures0.xml', $signatureXml)
            ->build();
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

        // A changed signature value. The replacement has to differ from what
        // was there: ECDSA picks a fresh k every run, so overwriting the first
        // base64 character with a constant leaves the signature untouched
        // about one run in sixty-four, and the container then validates.
        $brokenXml = preg_replace_callback(
            '/(<ds:SignatureValue[^>]*>)([A-Za-z0-9+\/])/',
            static fn(array $m): string => $m[1] . ($m[2] === 'A' ? 'B' : 'A'),
            $signatureXml,
            1,
        );
        self::assertIsString($brokenXml);
        self::assertNotSame($signatureXml, $brokenXml);
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
            $bytes = self::withEncapsulated($result, 'EncapsulatedOCSPValue', self::ocspAnswer($after, $keyPair->certificate));

            $report = self::validator($fixture)->validate($bytes);
            $signature = $report->signatures[0];
            self::assertSame($indication, $signature->indication, $how);
            self::assertSame($subIndication, $signature->subIndication, $how);
            self::assertTrue($signature->has($code), $how);
        }
    }

    /**
     * #14: a genuine revocation answer signed with SHA-1 no longer proves
     * anything, and nothing shows it was made while SHA-1 still counted.
     */
    public function testARevocationAnswerSignedWithSha1IsIndeterminate(): void
    {
        $fixture = new SigningFixture();
        $keyPair = TestPki::signerEc256();
        $result = $fixture->signingService->signWith(AsicContainer::create(DataFile::fromString('a.txt', 'x')), LocalKeySigner::fromKeyPair($keyPair));

        $after = new SigningFixture($fixture->clock);
        $after->ocsp->sign = TestSignatures::sha1(TestKey::fixture('ocsp'));
        $bytes = self::withEncapsulated($result, 'EncapsulatedOCSPValue', self::ocspAnswer($after, $keyPair->certificate));

        $signature = self::validator($fixture)->validate($bytes)->signatures[0];
        self::assertSame(Indication::Indeterminate, $signature->indication);
        self::assertSame(SubIndication::CryptoConstraintsFailureNoPoe, $signature->subIndication);
        self::assertTrue($signature->has(FindingCodes::REVOCATION_WEAK_ALGORITHM));
        self::assertFalse($signature->has(FindingCodes::REVOCATION_INVALID));
    }

    /**
     * #14: an intermediate CA certificate signed with SHA-1, beneath a signer
     * whose own certificate and signature are sound.
     */
    public function testACertificateChainSignedWithSha1IsIndeterminate(): void
    {
        $intermediateKey = TestKey::ec(label: 'sha1-intermediate');
        $intermediate = TestCertificates::issue($intermediateKey, ['id-at-commonName' => 'allkiri Test SHA-1 Intermediate'], [
            'id-ce-basicConstraints' => [['cA' => true], true],
            'id-ce-keyUsage' => [['keyCertSign', 'cRLSign'], true],
            'id-pe-authorityInfoAccess' => null,
        ], signature: TestCertificateSignature::Sha1);
        $signer = TestCertificates::issue(
            TestKey::ec(label: 'sha1-intermediate-signer'),
            ['id-at-commonName' => 'ALLKIRI,TESTER,38001085718'],
            ['id-ce-keyUsage' => [['digitalSignature', 'nonRepudiation'], true]],
            TestIssuer::of($intermediate, $intermediateKey),
        );

        // Signing trusts the intermediate itself, so the SHA-1 link is never
        // walked there; it only puts the intermediate into the signature.
        $fixture = new SigningFixture(extraCas: [$intermediate->certificate]);
        $result = $fixture->signingService->signWith(AsicContainer::create(DataFile::fromString('a.txt', 'x')), LocalKeySigner::fromKeyPair($signer));
        $bytes = (new AsicWriter())->write($result->container);

        // Validation trusts only the root, so the chain has to go through it.
        $rootOnly = (new SigningFixture($fixture->clock))->trustStore;
        $signature = self::validator($fixture)->validate($bytes, 'a.asice', new ValidationOptions(trustStore: $rootOnly))->signatures[0];
        self::assertSame(Indication::Indeterminate, $signature->indication);
        self::assertSame(SubIndication::CryptoConstraintsFailureNoPoe, $signature->subIndication);
        self::assertTrue($signature->has(FindingCodes::CHAIN_WEAK_ALGORITHM));
        self::assertFalse($signature->has(FindingCodes::CHAIN_INVALID));
    }

    /**
     * #15: an authentication certificate from the same CA is not a certificate
     * for signing. The signing service would refuse it, so the signature is
     * finalised here without prepare(), as another tool could have made it.
     */
    public function testASignatureByACertificateNotForSigningIsIndeterminate(): void
    {
        $fixture = new SigningFixture();
        $container = AsicContainer::create(DataFile::fromString('a.txt', 'x'));
        $card = TestPki::cardAuth();
        $algorithm = SignatureAlgorithm::forKey($card->certificate->publicKey());
        $built = (new SignatureBuilder($fixture->clock))->build($container->dataFiles, $card->certificate, $algorithm);
        $prepared = new DataToBeSigned(
            $built->signatureId,
            $container->nextSignatureFileName(),
            $algorithm,
            $built->digest(),
            $built->signedInfoCanonical,
            $built->document->toXml(),
            $card->certificate,
            $container->fingerprint(),
            SignatureLevel::LT,
            $fixture->clock->now(),
        );
        $result = $fixture->signingService->finalize($container, $prepared, LocalKeySigner::fromKeyPair($card)->sign($prepared));

        $signature = self::validator($fixture)->validate((new AsicWriter())->write($result->container))->signatures[0];

        self::assertSame(Indication::Indeterminate, $signature->indication);
        self::assertSame(SubIndication::ChainConstraintsFailure, $signature->subIndication);
        self::assertSame([FindingCodes::SIGNING_CERTIFICATE_KEY_USAGE], array_map(static fn($f): string => $f->code, $signature->errors()));
    }

    /**
     * #15: a CA with a path length constraint of 0, and a CA below it that it
     * was not allowed to have, carried in the signature's own certificates.
     */
    public function testAChainThatBreaksAPathLengthConstraintIsIndeterminate(): void
    {
        $limitedKey = TestKey::ec(label: 'validation pathLen 0 CA');
        $limited = TestIssuer::of(TestCertificates::issue($limitedKey, ['id-at-commonName' => 'allkiri Limited CA'], [
            'id-ce-basicConstraints' => [['cA' => true, 'pathLenConstraint' => new BigInteger(0)], true],
            'id-ce-keyUsage' => [['keyCertSign', 'cRLSign'], true],
            'id-pe-authorityInfoAccess' => null,
        ]), $limitedKey);
        $belowKey = TestKey::ec(label: 'validation CA below pathLen 0');
        $below = TestCertificates::issue($belowKey, ['id-at-commonName' => 'allkiri CA Below The Limit'], [
            'id-ce-basicConstraints' => [['cA' => true], true],
            'id-ce-keyUsage' => [['keyCertSign', 'cRLSign'], true],
            'id-pe-authorityInfoAccess' => null,
        ], $limited);
        $signer = TestCertificates::issue(
            TestKey::ec(label: 'validation signer below pathLen 0'),
            ['id-at-commonName' => 'ALLKIRI,TESTER,38001085718'],
            ['id-ce-keyUsage' => [['digitalSignature', 'nonRepudiation'], true]],
            TestIssuer::of($below, $belowKey),
        );

        // Signing trusts the lower CA directly; validation trusts only the root,
        // with the limited CA added to the signature's certificates.
        $fixture = new SigningFixture(extraCas: [$below->certificate]);
        $result = $fixture->signingService->signWith(AsicContainer::create(DataFile::fromString('a.txt', 'x')), LocalKeySigner::fromKeyPair($signer));
        $xml = (string) $result->container->signatureFile('META-INF/signatures0.xml')?->xml;
        $withLimited = str_replace('</xades:CertificateValues>', '<xades:EncapsulatedX509Certificate>' . $limited->certificate->base64() . '</xades:EncapsulatedX509Certificate></xades:CertificateValues>', $xml, $count);
        self::assertSame(1, $count);

        $rootOnly = (new SigningFixture($fixture->clock))->trustStore;
        $signature = self::validator($fixture)->validate(self::containerOfA($withLimited), 'a.asice', new ValidationOptions(trustStore: $rootOnly))->signatures[0];

        self::assertSame(Indication::Indeterminate, $signature->indication);
        self::assertSame(SubIndication::ChainConstraintsFailure, $signature->subIndication);
        self::assertTrue($signature->has(FindingCodes::CHAIN_CONSTRAINT_VIOLATED));
    }

    /**
     * #27: RSASSA-PSS everywhere beneath the signature: on the signer's
     * certificate, on the timestamp and on the revocation answer.
     */
    public function testASignatureRestingOnRsassaPssValidates(): void
    {
        $tsa = TestCertificates::issue(TestPki::signerRsa(), ['id-at-commonName' => 'allkiri PSS TSA'], ['id-ce-extKeyUsage' => [['id-kp-timeStamping'], true]], signature: TestCertificateSignature::Pss256);
        $responder = TestCertificates::issue(TestPki::signerRsa(), ['id-at-commonName' => 'allkiri PSS OCSP Responder'], ['id-ce-extKeyUsage' => [['id-kp-OCSPSigning'], false]], signature: TestCertificateSignature::Pss256);
        $signer = TestCertificates::issue(
            TestKey::ec(label: 'signer issued with PSS'),
            ['id-at-commonName' => 'ALLKIRI,TESTER,38001085718'],
            ['id-ce-keyUsage' => [['digitalSignature', 'nonRepudiation'], true]],
            signature: TestCertificateSignature::Pss256,
        );
        $fixture = new SigningFixture(tsa: $tsa, ocspResponder: $responder);
        $fixture->tsa->sign = TestSignatures::pss(TestKey::fixture('signer-rsa'));
        $fixture->ocsp->sign = TestSignatures::pss(TestKey::fixture('signer-rsa'));

        $result = $fixture->signingService->signWith(AsicContainer::create(DataFile::fromString('a.txt', 'x')), LocalKeySigner::fromKeyPair($signer));
        $signature = self::validator($fixture)->validate((new AsicWriter())->write($result->container))->signatures[0];

        self::assertSame(Indication::TotalPassed, $signature->indication, implode('; ', array_map(static fn($f): string => $f->code . ': ' . $f->message, $signature->errors())));
    }

    public function testATimestampSignedWithSha1IsIndeterminate(): void
    {
        $fixture = new SigningFixture();
        $result = $fixture->signingService->signWith(AsicContainer::create(DataFile::fromString('a.txt', 'x')), LocalKeySigner::fromKeyPair(TestPki::signerEc256()));
        $xml = (string) $result->container->signatureFile('META-INF/signatures0.xml')?->xml;
        self::assertSame(1, preg_match('#<xades:EncapsulatedTimeStamp[^>]*>([^<]+)#', $xml, $match));
        $original = TimestampToken::fromDer((string) base64_decode($match[1], true));

        // The same imprint, timestamped again by an authority that signs with SHA-1.
        $after = new SigningFixture($fixture->clock);
        $after->tsa->sign = TestSignatures::sha1(TestKey::fixture('tsa'));
        $request = TimestampRequest::build(HashAlgorithm::SHA256, $original->tstInfo()->messageImprint);
        $token = TimestampResponse::fromDer($after->tsa->handle(HttpRequest::post(MockTsa::URL, 'application/timestamp-query', $request->der))->body)->token();
        self::assertNotNull($token);
        $bytes = self::withEncapsulated($result, 'EncapsulatedTimeStamp', $token->der());

        $signature = self::validator($fixture)->validate($bytes)->signatures[0];
        self::assertSame(Indication::Indeterminate, $signature->indication);
        self::assertSame(SubIndication::CryptoConstraintsFailureNoPoe, $signature->subIndication);
        self::assertTrue($signature->has(FindingCodes::TIMESTAMP_WEAK_ALGORITHM));
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
        // The same floor applies beneath the signature: the test CA's key is 3072 bits.
        self::assertTrue($report->signatures[0]->has(FindingCodes::CHAIN_WEAK_ALGORITHM));

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

    /**
     * @return iterable<string, array{\Closure(string): string, string}>
     */
    public static function signatureWrappings(): iterable
    {
        yield 'a copy of the signed properties carrying the same Id' => [static fn(string $xml): string => SignatureWrapping::duplicateId($xml), FindingCodes::DUPLICATE_ID];
        yield 'a copy carrying the Id, the original renamed' => [static fn(string $xml): string => SignatureWrapping::renamedOriginal($xml), FindingCodes::SIGNED_PROPERTIES_REFERENCE_MISSING];
    }

    /**
     * XML signature wrapping. The digests and the signature value still check
     * out, so what has to fail is the binding between the reference and the
     * properties that are reported.
     *
     * @param \Closure(string): string $wrap
     */
    #[DataProvider('signatureWrappings')]
    public function testSignedPropertiesCannotBeSwappedForAnUntouchedCopy(\Closure $wrap, string $expectedCode): void
    {
        $fixture = new SigningFixture();
        $result = $fixture->signingService->signWith(
            AsicContainer::create(DataFile::fromString('a.txt', 'original')),
            LocalKeySigner::fromKeyPair(TestPki::signerEc256()),
        );
        $signatureXml = (string) $result->container->signatureFile('META-INF/signatures0.xml')?->xml;
        $wrapped = (new ZipWriter())
            ->addStored('mimetype', Ns::MIME_ASICE)
            ->addDeflated('a.txt', 'original')
            ->addDeflated('META-INF/manifest.xml', Manifest::forDataFiles([DataFile::fromString('a.txt', 'original')])->toXml())
            ->addDeflated('META-INF/signatures0.xml', $wrap($signatureXml))
            ->build();

        $signature = self::validator($fixture)->validate($wrapped)->signatures[0];

        self::assertSame(Indication::TotalFailed, $signature->indication);
        self::assertContains($expectedCode, $signature->codes());
        self::assertNotContains(FindingCodes::SIGNATURE_INVALID, $signature->codes(), 'the signature value still verifies');
        self::assertNull($signature->info->claimedSigningTime, 'the altered signing time must not reach the report');
    }

    /**
     * The reproduction from the audit, on a container digidoc4j made.
     */
    public function testTheReportedWrappingOfADigidoc4jContainerIsCaught(): void
    {
        $zip = new ZipWriter();
        foreach (ZipReader::read((string) file_get_contents(self::CONTAINERS . 'valid-asice.asice')) as $entry) {
            if ($entry->name === 'META-INF/signatures0.xml') {
                $zip->addDeflated($entry->name, SignatureWrapping::duplicateId($entry->content()));
            } else {
                $zip->addEntry($entry);
            }
        }
        $fixture = new SigningFixture(new FrozenClock('2026-09-11T00:00:00Z'));

        $signature = self::validator($fixture)->validate($zip->build())->signatures[0];

        self::assertSame(Indication::TotalFailed, $signature->indication);
        self::assertContains(FindingCodes::DUPLICATE_ID, $signature->codes());
        self::assertNull($signature->info->claimedSigningTime);
    }

    public function testAnArchiveThatReadersCouldReadDifferentlyIsNotAContainer(): void
    {
        $sound = (new ZipWriter())
            ->addStored('mimetype', Ns::MIME_ASICE)
            ->addStored('a.txt', 'checked')
            ->addStored('b.txt', 'shown')
            ->build();

        $report = self::validator(new SigningFixture())->validate(str_replace('b.txt', 'a.txt', $sound));

        self::assertFalse($report->isValid());
        self::assertSame(FindingCodes::NOT_A_CONTAINER, $report->containerFindings[0]->code);
        self::assertStringContainsString('more than one entry named "a.txt"', $report->containerFindings[0]->message);
    }

    /**
     * A validator's input comes from strangers. Whatever in it cannot be read
     * becomes a finding; nothing escapes as an exception.
     */
    public function testWhatCannotBeReadIsReportedNotThrown(): void
    {
        $fixture = new SigningFixture();
        $keyPair = TestPki::signerEc256();
        $result = $fixture->signingService->signWith(AsicContainer::create(DataFile::fromString('a.txt', 'x')), LocalKeySigner::fromKeyPair($keyPair));
        $xml = (string) $result->container->signatureFile('META-INF/signatures0.xml')?->xml;
        self::assertSame(1, preg_match('#<xades:EncapsulatedTimeStamp[^>]*>([^<]+)#', $xml, $match));
        $imprint = TimestampToken::fromDer((string) base64_decode($match[1], true))->tstInfo()->messageImprint;
        // The token a fixture's authority would give for the same imprint, taken
        // from the response without parsing it, since some of these do not parse.
        $tokenFrom = static function (SigningFixture $authority) use ($imprint): string {
            $request = TimestampRequest::build(HashAlgorithm::SHA256, $imprint);

            return Asn1::decodeRaw($authority->tsa->handle(HttpRequest::post(MockTsa::URL, 'application/timestamp-query', $request->der))->body)->child(1)->der();
        };
        $twoSigners = new SigningFixture($fixture->clock);
        $twoSigners->tsa->signerInfoCopies = 2;
        $unreadableTsa = new SigningFixture($fixture->clock, tsa: new KeyPair(TestPki::tsa()->privateKey, DerPatch::unreadableKey(TestPki::tsa()->certificate)));
        $unreadableResponder = new SigningFixture($fixture->clock, ocspResponder: new KeyPair(TestPki::ocspResponder()->privateKey, DerPatch::unreadableKey(TestPki::ocspResponder()->certificate)));
        $plain = new SigningFixture($fixture->clock);

        $cases = [
            'a timestamp authority whose key cannot be read' => ['EncapsulatedTimeStamp', $tokenFrom($unreadableTsa), FindingCodes::TIMESTAMP_INVALID],
            'a timestamp claiming two signers' => ['EncapsulatedTimeStamp', $tokenFrom($twoSigners), FindingCodes::TIMESTAMP_INVALID],
            'a timestamp carrying something that is not a certificate' => ['EncapsulatedTimeStamp', DerPatch::withoutCertificate($tokenFrom($plain), TestPki::tsa()->certificate), FindingCodes::TIMESTAMP_INVALID],
            'an OCSP responder whose key cannot be read' => ['EncapsulatedOCSPValue', self::ocspAnswer($unreadableResponder, $keyPair->certificate), FindingCodes::REVOCATION_INVALID],
            'an OCSP response carrying something that is not a certificate' => ['EncapsulatedOCSPValue', DerPatch::withoutCertificate(self::ocspAnswer($plain, $keyPair->certificate), TestPki::ocspResponder()->certificate), FindingCodes::REVOCATION_INVALID],
        ];
        foreach ($cases as $case => [$element, $der, $code]) {
            $signature = self::validator($fixture)->validate(self::withEncapsulated($result, $element, $der))->signatures[0];
            self::assertContains($code, $signature->codes(), $case);
        }

        // A signing certificate whose key cannot be read.
        $unreadableSigner = str_replace($keyPair->certificate->base64(), DerPatch::unreadableKey($keyPair->certificate)->base64(), $xml, $count);
        self::assertSame(1, $count);
        $signature = self::validator($fixture)->validate(self::containerOfA($unreadableSigner))->signatures[0];
        self::assertContains(FindingCodes::WEAK_KEY, $signature->codes());
        self::assertContains(FindingCodes::SIGNATURE_INVALID, $signature->codes());
    }

    public function testAnOcspResponseNestedTooDeeplyIsReportedRatherThanFatal(): void
    {
        $fixture = new SigningFixture();
        $result = $fixture->signingService->signWith(
            AsicContainer::create(DataFile::fromString('a.txt', 'original')),
            LocalKeySigner::fromKeyPair(TestPki::signerEc256()),
        );
        $signatureXml = (string) $result->container->signatureFile('META-INF/signatures0.xml')?->xml;
        // About 80 KB, which exhausted a 128 MB memory limit inside phpseclib.
        $nested = base64_encode(\Allkiri\Tests\Support\Crypto\DeepDer::nested(20_000));
        $hostileXml = preg_replace('#(<xades:EncapsulatedOCSPValue>)[^<]+#', '${1}' . $nested, $signatureXml, 1, $replaced);
        self::assertSame(1, $replaced);
        $hostile = (new ZipWriter())
            ->addStored('mimetype', Ns::MIME_ASICE)
            ->addDeflated('a.txt', 'original')
            ->addDeflated('META-INF/manifest.xml', Manifest::forDataFiles([DataFile::fromString('a.txt', 'original')])->toXml())
            ->addDeflated('META-INF/signatures0.xml', (string) $hostileXml)
            ->build();

        $signature = self::validator($fixture)->validate($hostile)->signatures[0];

        self::assertNotSame(Indication::TotalPassed, $signature->indication);
        self::assertContains(FindingCodes::REVOCATION_INVALID, $signature->codes());
        self::assertStringContainsString('DER nests deeper than 64 levels', implode("\n", array_map(static fn($f): string => $f->message, $signature->findings)));
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
