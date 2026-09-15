<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Signing;

use Allkiri\Container\AsicContainer;
use Allkiri\Container\AsicReader;
use Allkiri\Container\AsicWriter;
use Allkiri\Container\DataFile;
use Allkiri\Crypto\EcdsaSignature;
use Allkiri\Crypto\KeyPair;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Crypto\Tsp\TimestampVerificationException;
use Allkiri\Signing\CertificateNotForSigningException;
use Allkiri\Signing\DataToBeSigned;
use Allkiri\Signing\InvalidSignatureValueException;
use Allkiri\Signing\LocalKeySigner;
use Allkiri\Signing\SessionMismatchException;
use Allkiri\Signing\SignatureLevel;
use Allkiri\Signing\SigningException;
use Allkiri\Signing\SigningOptions;
use Allkiri\Tests\Support\Pki\TestCertificates;
use Allkiri\Tests\Support\Pki\TestCertificateSignature;
use Allkiri\Tests\Support\Pki\TestIssuer;
use Allkiri\Tests\Support\Pki\TestKey;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Tests\Support\Pki\TestSignatures;
use Allkiri\Tests\Support\SigningFixture;
use Allkiri\Tests\Support\Trust\SwitchableTrustStore;
use Allkiri\Trust\ChainBuildingException;
use Allkiri\Trust\TrustedList\TrustedListException;
use Allkiri\Xades\Dsig\ArrayReferenceResolver;
use Allkiri\Xades\Dsig\XmlDsigVerifier;
use Allkiri\Xades\Model\XadesSignatureParser;
use Allkiri\Xades\Ns;
use Allkiri\Xades\SignatureDocument;
use Allkiri\Xades\SignatureProfile;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class SigningServiceTest extends TestCase
{
    private static function container(): AsicContainer
    {
        return AsicContainer::create(DataFile::fromString('leping.txt', "Tere, allkiri!\n"));
    }

    /**
     * @return iterable<string, array{KeyPair, SignatureAlgorithm}>
     */
    public static function signers(): iterable
    {
        yield 'ECDSA P-256' => [TestPki::signerEc256(), SignatureAlgorithm::ES256];
        yield 'ECDSA P-384' => [TestPki::signerEc384(), SignatureAlgorithm::ES384];
        yield 'RSA PKCS#1' => [TestPki::signerRsa(), SignatureAlgorithm::RS256];
        yield 'RSA PSS' => [TestPki::signerRsa(), SignatureAlgorithm::PS256];
    }

    #[DataProvider('signers')]
    public function testAnLtSignatureIsProducedAndVerifiesForEveryAlgorithm(KeyPair $keyPair, SignatureAlgorithm $algorithm): void
    {
        $fixture = new SigningFixture();
        $container = self::container();

        $result = $fixture->signingService->signWith(
            $container,
            LocalKeySigner::fromKeyPair($keyPair),
            (new SigningOptions())->withAlgorithm($algorithm),
        );

        self::assertSame(SignatureLevel::LT, $result->level);
        self::assertSame('META-INF/signatures0.xml', $result->signatureFileName);
        self::assertSame([], $result->warnings);
        self::assertSame('2026-03-01T10:00:00+00:00', $result->timestampTime?->format(DATE_ATOM));
        self::assertSame('2026-03-01T10:00:00+00:00', $result->ocspProducedAt?->format(DATE_ATOM));
        self::assertSame(1, $fixture->tsa->requests);
        self::assertSame(1, $fixture->ocsp->requests);

        // The signature verifies as XML-DSig, on its own terms.
        $file = $result->container->signatureFile('META-INF/signatures0.xml');
        self::assertNotNull($file);
        $document = SignatureDocument::parse($file->xml);
        $verification = (new XmlDsigVerifier())->verify($document->signatures()[0], new ArrayReferenceResolver(['leping.txt' => "Tere, allkiri!\n"]));
        self::assertSame([], $verification->problems);
        self::assertTrue($verification->isValid());
        self::assertSame($algorithm->xmlUri(), $verification->signatureMethod);
        self::assertTrue($verification->certificate?->equals($keyPair->certificate));

        // And it has the XAdES-LT parts, in the order the profile requires.
        $parsed = (new XadesSignatureParser())->parse($document->signatures()[0]);
        self::assertSame([], $parsed->warnings);
        self::assertSame('2026-03-01T10:00:00+00:00', $parsed->signingTime?->format(DATE_ATOM));
        self::assertTrue($parsed->signingCertificateIsV2);
        self::assertCount(1, $parsed->signingCertificateReferences);
        self::assertSame($keyPair->certificate->fingerprint(), $parsed->signingCertificateReferences[0]['digest']);
        self::assertNotNull($parsed->signingCertificateReferences[0]['issuerSerialV2']);
        self::assertFalse($parsed->hasSignaturePolicyIdentifier, 'BDOC-TM is dead and must not appear');
        self::assertCount(1, $parsed->signatureTimestamps);
        self::assertSame(Ns::C14N_EXC, $parsed->signatureTimestamps[0]['canonicalizationMethod']);
        self::assertCount(1, $parsed->ocspValues);
        self::assertNotSame([], $parsed->certificateValues);
        self::assertSame(0, $parsed->archiveTimestampCount);
        self::assertSame([['objectReference' => '#r-' . $parsed->id . '-1', 'mimeType' => 'text/plain']], $parsed->dataObjectFormats);

        $order = self::elementOrder($document, $parsed->id);
        self::assertSame(['SignatureTimeStamp', 'CertificateValues', 'RevocationValues'], $order);

        // The container is a well-formed ASiC-E that reads back.
        $bytes = (new AsicWriter())->write($result->container);
        $reread = (new AsicReader())->read($bytes);
        self::assertSame([], $reread->structuralFindings);
        self::assertCount(1, $reread->signatureFiles);
        self::assertSame("Tere, allkiri!\n", $reread->dataFiles[0]->content);
    }

    public function testTheTimestampCoversTheSignatureValueAndTheOcspCoversTheSigner(): void
    {
        $fixture = new SigningFixture();
        $result = $fixture->signingService->signWith(self::container(), LocalKeySigner::fromKeyPair(TestPki::signerEc256()));

        $file = $result->container->signatureFile('META-INF/signatures0.xml');
        self::assertNotNull($file);
        $document = SignatureDocument::parse($file->xml);
        $parsed = (new XadesSignatureParser())->parse($document->signatures()[0]);

        // The timestamp's imprint is the digest of the canonicalised SignatureValue element.
        $token = \Allkiri\Crypto\Tsp\TimestampToken::fromDer($parsed->signatureTimestamps[0]['token']);
        $signatureValue = \Allkiri\Xades\Dsig\Xml::element($document->xpath(), 'ds:SignatureValue', $document->signatures()[0]);
        self::assertNotNull($signatureValue);
        $expected = \Allkiri\Crypto\HashAlgorithm::SHA256->digest((new \Allkiri\Xades\Dsig\Canonicalizer())->canonicalize($signatureValue, Ns::C14N_EXC));
        self::assertSame($expected, $token->tstInfo()->messageImprint);

        // The OCSP response answers about the signer's certificate.
        $ocsp = \Allkiri\Crypto\Ocsp\OcspResponse::fromDer($parsed->ocspValues[0]);
        $single = $ocsp->basic()?->responses()[0];
        self::assertNotNull($single);
        self::assertTrue($single->certId->equals(\Allkiri\Crypto\Ocsp\CertId::for(TestPki::signerEc256()->certificate, TestPki::ca()->certificate)));
        self::assertSame(\Allkiri\Crypto\Ocsp\CertStatus::Good, $single->status);

        // CertificateValues carries the CA, the responder and the TSA, but not the signer.
        $subjects = array_map(static fn($c): string => (string) $c->commonName(), $parsed->certificateValues);
        self::assertContains('allkiri Test CA', $subjects);
        self::assertContains('allkiri Test OCSP Responder', $subjects);
        self::assertContains('allkiri Test TSA', $subjects);
        self::assertNotContains('ALLKIRI,TESTER,38001085718', $subjects, 'the signer is already in ds:KeyInfo');
    }

    public function testLevelBAndTStopWhereTheyShould(): void
    {
        $fixture = new SigningFixture();
        $signer = LocalKeySigner::fromKeyPair(TestPki::signerEc256());

        $b = $fixture->besOnlyService()->signWith(self::container(), $signer, (new SigningOptions())->withLevel(SignatureLevel::B));
        self::assertSame(SignatureLevel::B, $b->level);
        self::assertNull($b->timestampTime);
        self::assertSame(0, $fixture->tsa->requests);

        $t = $fixture->signingService->signWith(self::container(), $signer, (new SigningOptions())->withLevel(SignatureLevel::T));
        self::assertSame(SignatureLevel::T, $t->level);
        self::assertNotNull($t->timestampTime);
        self::assertNull($t->ocspProducedAt);
        self::assertSame(1, $fixture->tsa->requests);
        self::assertSame(0, $fixture->ocsp->requests, 'a T signature asks no revocation question');

        $file = $t->container->signatureFile('META-INF/signatures0.xml');
        self::assertNotNull($file);
        $parsed = (new XadesSignatureParser())->parse(SignatureDocument::parse($file->xml)->signatures()[0]);
        self::assertCount(1, $parsed->signatureTimestamps);
        self::assertSame([], $parsed->ocspValues);

        $this->expectException(SigningException::class);
        $fixture->besOnlyService()->prepare(self::container(), TestPki::signerEc256()->certificate);
    }

    public function testTheSessionSurvivesJsonAndRejectsMismatches(): void
    {
        $fixture = new SigningFixture();
        $container = self::container();
        $keyPair = TestPki::signerEc256();

        $prepared = $fixture->signingService->prepare($container, $keyPair->certificate);
        $restored = DataToBeSigned::fromJson((string) json_encode($prepared));

        self::assertSame($prepared->signatureId, $restored->signatureId);
        self::assertSame($prepared->digest, $restored->digest);
        self::assertSame($prepared->signedInfoCanonical, $restored->signedInfoCanonical);
        self::assertSame($prepared->signatureXml, $restored->signatureXml);
        self::assertSame($prepared->containerFingerprint, $restored->containerFingerprint);
        self::assertSame($prepared->algorithm, $restored->algorithm);
        self::assertSame($prepared->level, $restored->level);
        self::assertTrue($restored->signerCertificate->equals($keyPair->certificate));
        self::assertSame('SHA256', $restored->hashName());
        self::assertSame(base64_encode($prepared->digest), $restored->digestBase64());
        self::assertSame(bin2hex($prepared->digest), $restored->digestHex());

        // The digest really is the digest of what gets signed.
        self::assertSame(hash('sha256', $prepared->signedInfoCanonical, true), $prepared->digest);

        // Finishing against different content is refused.
        $other = AsicContainer::create(DataFile::fromString('leping.txt', 'something else'));
        $value = $keyPair->privateKey->sign($restored->algorithm, $restored->signedInfoCanonical);
        try {
            $fixture->signingService->finalize($other, $restored, $value);
            self::fail('a session was finished against different data files');
        } catch (SessionMismatchException $e) {
            self::assertStringContainsString('data files changed', $e->getMessage());
        }

        // Or against a container that has meanwhile gained a signature.
        $signed = $fixture->signingService->finalize($container, $restored, $value)->container;
        try {
            $fixture->signingService->finalize($signed, $restored, $value);
            self::fail('a session was replayed onto an already signed container');
        } catch (SessionMismatchException $e) {
            self::assertStringContainsString('signatures1.xml', $e->getMessage());
        }
    }

    public function testAMutatedPreparedDocumentIsRefused(): void
    {
        $fixture = new SigningFixture();
        $container = self::container();
        $keyPair = TestPki::signerEc256();
        $prepared = $fixture->signingService->prepare($container, $keyPair->certificate);
        $value = $keyPair->privateKey->sign($prepared->algorithm, $prepared->signedInfoCanonical);

        // Someone edits the stored XML between the two requests.
        $tampered = new DataToBeSigned(
            $prepared->signatureId,
            $prepared->signatureFileName,
            $prepared->algorithm,
            $prepared->digest,
            $prepared->signedInfoCanonical,
            str_replace('text/plain', 'application/pdf', $prepared->signatureXml),
            $prepared->signerCertificate,
            $prepared->containerFingerprint,
            $prepared->level,
            $prepared->createdAt,
        );

        $this->expectException(SessionMismatchException::class);
        $fixture->signingService->finalize($container, $tampered, $value);
    }

    public function testSignatureValuesAreCheckedBeforeAnythingIsSpent(): void
    {
        $fixture = new SigningFixture();
        $container = self::container();
        $keyPair = TestPki::signerEc256();
        $prepared = $fixture->signingService->prepare($container, $keyPair->certificate);

        foreach ([
            'empty' => '',
            'wrong length' => str_repeat("\x01", 63),
            'wrong key' => TestPki::signerEc384()->privateKey->sign(SignatureAlgorithm::ES256, $prepared->signedInfoCanonical),
        ] as $label => $value) {
            try {
                $fixture->signingService->finalize($container, $prepared, $value);
                self::fail(\sprintf('a %s signature value was accepted', $label));
            } catch (InvalidSignatureValueException) {
            }
        }
        self::assertSame(0, $fixture->tsa->requests, 'no timestamp was bought for a bad signature');
        self::assertSame(0, $fixture->ocsp->requests);

        // A DER-encoded ECDSA value is accepted and converted to the r‖s form.
        $der = EcdsaSignature::rawToDer($keyPair->privateKey->sign($prepared->algorithm, $prepared->signedInfoCanonical));
        $result = $fixture->signingService->finalize($container, $prepared, $der);
        self::assertSame(SignatureLevel::LT, $result->level);
    }

    public function testTheProfileControlsWhatEndsUpInTheSignature(): void
    {
        $fixture = new SigningFixture();
        $profile = new SignatureProfile(
            signatureId: 'S0',
            claimedRoles: ['Juhatuse liige'],
            city: 'Tallinn',
            country: 'EE',
        );

        $result = $fixture->signingService->signWith(
            self::container(),
            LocalKeySigner::fromKeyPair(TestPki::signerRsa()),
            (new SigningOptions())->withProfile($profile),
        );

        self::assertSame('S0', $result->signatureId);
        $file = $result->container->signatureFile('META-INF/signatures0.xml');
        self::assertNotNull($file);
        $parsed = (new XadesSignatureParser())->parse(SignatureDocument::parse($file->xml)->signatures()[0]);
        self::assertSame('S0', $parsed->id);
        self::assertSame(['Juhatuse liige'], $parsed->claimedRoles);
        self::assertSame('Tallinn, EE', $parsed->productionPlace);

        // SigningCertificate v1 on request, for validators that ask for it.
        $v1 = $fixture->signingService->signWith(
            self::container(),
            LocalKeySigner::fromKeyPair(TestPki::signerRsa()),
            (new SigningOptions())->withProfile(new SignatureProfile(useSigningCertificateV2: false)),
        );
        $v1File = $v1->container->signatureFile('META-INF/signatures0.xml');
        self::assertNotNull($v1File);
        $v1Parsed = (new XadesSignatureParser())->parse(SignatureDocument::parse($v1File->xml)->signatures()[0]);
        self::assertFalse($v1Parsed->signingCertificateIsV2);
        self::assertSame(TestPki::signerRsa()->certificate->serialNumber(), $v1Parsed->signingCertificateReferences[0]['serialNumber']);
    }

    public function testSigningIsReproducibleWithAFixedProfile(): void
    {
        $bytes = [];
        foreach ([0, 1] as $ignored) {
            $fixture = new SigningFixture();
            $result = $fixture->besOnlyService()->signWith(
                self::container(),
                LocalKeySigner::fromKeyPair(TestPki::signerRsa()),
                (new SigningOptions())->withLevel(SignatureLevel::B)->withProfile(new SignatureProfile(signatureId: 'S0')),
            );
            $bytes[] = (new AsicWriter())->write($result->container);
        }

        // With RSA PKCS#1 (deterministic), a frozen clock and a fixed signature
        // Id, the XML and the archive around it must come out byte for byte the
        // same. An LT signature never can: a timestamp token and an OCSP
        // response are fresh every time, and both are signed with ECDSA here.
        self::assertSame(bin2hex($bytes[0]), bin2hex($bytes[1]));
    }

    public function testARevokedSignerCannotSign(): void
    {
        $fixture = new SigningFixture();
        $keyPair = TestPki::signerEc256();
        $fixture->ocsp->revoke($keyPair->certificate->serialNumber(), new \DateTimeImmutable('2026-02-01T00:00:00Z'));

        $this->expectException(SigningException::class);
        $this->expectExceptionMessageMatches('/revoked/i');
        $fixture->signingService->signWith(self::container(), LocalKeySigner::fromKeyPair($keyPair));
    }

    public function testAnOcspResponseOlderThanTheTimestampIsRefused(): void
    {
        $fixture = new SigningFixture();
        $fixture->ocsp->producedAtOffsetSeconds = -120;

        try {
            $fixture->signingService->signWith(self::container(), LocalKeySigner::fromKeyPair(TestPki::signerEc256()));
            self::fail('an OCSP response older than the timestamp was accepted');
        } catch (SigningException $e) {
            self::assertStringContainsString('before the timestamp', $e->getMessage());
        }
    }

    /**
     * #15: an authentication certificate chains to the same CA as a signing
     * one, but every validator refuses what it signs, so nothing is spent on it.
     */
    public function testACertificateThatIsNotForSigningIsRefusedBeforeAnythingIsSpent(): void
    {
        $fixture = new SigningFixture();

        try {
            $fixture->signingService->signWith(self::container(), LocalKeySigner::fromKeyPair(TestPki::cardAuth()));
            self::fail('an authentication certificate was used to sign');
        } catch (CertificateNotForSigningException $e) {
            self::assertStringContainsString('nonRepudiation', $e->getMessage());
        }
        self::assertSame(0, $fixture->tsa->requests);
        self::assertSame(0, $fixture->ocsp->requests);
    }

    /**
     * #14: what a signature rests on is held to the same algorithms when it is
     * made as when it is validated, so none of these is completed.
     */
    public function testATimestampSignedWithSha1IsRefused(): void
    {
        $fixture = new SigningFixture();
        $fixture->tsa->sign = TestSignatures::sha1(TestKey::fixture('tsa'));

        try {
            $fixture->signingService->signWith(self::container(), LocalKeySigner::fromKeyPair(TestPki::signerEc256()));
            self::fail('a timestamp signed with SHA-1 was accepted');
        } catch (SigningException $e) {
            self::assertMatchesRegularExpression('/Token is signed with SHA-1/', $e->getMessage());
            $previous = $e->getPrevious();
            self::assertInstanceOf(TimestampVerificationException::class, $previous);
            self::assertSame(TimestampVerificationException::REASON_ALGORITHM_NOT_ACCEPTED, $previous->reason);
        }
    }

    public function testAnOcspResponseSignedWithSha1IsRefused(): void
    {
        $fixture = new SigningFixture();
        $fixture->ocsp->sign = TestSignatures::sha1(TestKey::fixture('ocsp'));

        $this->expectException(SigningException::class);
        $this->expectExceptionMessageMatches('/OCSP response is signed with SHA-1/');

        $fixture->signingService->signWith(self::container(), LocalKeySigner::fromKeyPair(TestPki::signerEc256()));
    }

    public function testASignerCertificateIssuedWithSha1IsRefused(): void
    {
        $signer = TestCertificates::issue(
            TestKey::ec(label: 'sha1-issued-signer'),
            ['id-at-commonName' => 'ALLKIRI,TESTER,38001085718'],
            ['id-ce-keyUsage' => [['digitalSignature', 'nonRepudiation'], true]],
            signature: TestCertificateSignature::Sha1,
        );

        $fixture = new SigningFixture();

        try {
            $fixture->signingService->signWith(self::container(), LocalKeySigner::fromKeyPair($signer));
            self::fail('a signer whose certificate is signed with SHA-1 signed');
        } catch (SigningException $e) {
            self::assertMatchesRegularExpression('/does not chain to a trusted CA: .* is signed with SHA-1/', $e->getMessage());
            self::assertInstanceOf(ChainBuildingException::class, $e->getPrevious());
        }
        self::assertSame(0, $fixture->tsa->requests, 'refused before a timestamp was bought');
    }

    /**
     * A signing certificate issued under the test TSA's certificate, which the
     * fixture trusts only as a timestamp authority.
     */
    private static function untrustedSigner(): KeyPair
    {
        return TestCertificates::issue(
            TestKey::ec(label: 'untrusted-signer'),
            ['id-at-commonName' => 'ALLKIRI,TESTER,38001085718'],
            ['id-ce-keyUsage' => [['digitalSignature', 'nonRepudiation'], true]],
            TestIssuer::of(TestPki::tsa(), TestKey::fixture('tsa')),
        );
    }

    private static function unreachableLists(): TrustedListException
    {
        return new TrustedListException(TrustedListException::REASON_TRANSPORT, 'Could not fetch the trusted list https://tl.test/list.xml: connection refused');
    }

    /**
     * @return iterable<string, array{SignatureLevel}>
     */
    public static function levelsThatRestOnTrust(): iterable
    {
        yield 'T' => [SignatureLevel::T];
        yield 'LT' => [SignatureLevel::LT];
    }

    /**
     * #24: a person with an untrusted certificate is refused before being asked
     * for a PIN, not after a timestamp has been bought for their signature.
     */
    #[DataProvider('levelsThatRestOnTrust')]
    public function testAnUntrustedSignerIsRefusedWhenPrepared(SignatureLevel $level): void
    {
        $fixture = new SigningFixture();

        try {
            $fixture->signingService->prepare(self::container(), self::untrustedSigner()->certificate, new SigningOptions($level));
            self::fail('an untrusted signer was prepared for');
        } catch (SigningException $e) {
            self::assertStringContainsString('does not chain to a trusted CA', $e->getMessage());
            self::assertInstanceOf(ChainBuildingException::class, $e->getPrevious());
        }
        self::assertSame(0, $fixture->tsa->requests);
        self::assertSame(0, $fixture->ocsp->requests);
    }

    public function testAnUntrustedSignerCanStillSignAtLevelB(): void
    {
        $fixture = new SigningFixture();

        $result = $fixture->signingService->signWith(self::container(), LocalKeySigner::fromKeyPair(self::untrustedSigner()), new SigningOptions(SignatureLevel::B));

        self::assertSame(SignatureLevel::B, $result->level);
        self::assertSame(0, $fixture->tsa->requests);
    }

    /**
     * Level T never asked for the chain at all: the timestamp was bought and
     * the signature finished.
     */
    public function testTheChainIsCheckedAgainBeforeATimestampIsBought(): void
    {
        $fixture = new SigningFixture();
        $store = new SwitchableTrustStore($fixture->trustStore);
        $service = $fixture->signingServiceTrusting($store);
        $keyPair = TestPki::signerEc256();
        $container = self::container();
        $prepared = $service->prepare($container, $keyPair->certificate, new SigningOptions(SignatureLevel::T));
        $store->failWith(self::unreachableLists());

        try {
            $service->finalize($container, $prepared, $keyPair->privateKey->sign($prepared->algorithm, $prepared->signedInfoCanonical));
            self::fail('a signature was finished without its chain being checked');
        } catch (SigningException $e) {
            self::assertStringContainsString('could not be loaded', $e->getMessage());
            self::assertInstanceOf(TrustedListException::class, $e->getPrevious());
        }
        self::assertSame(0, $fixture->tsa->requests, 'no timestamp was bought');
    }

    public function testTrustedListsThatCannotBeLoadedAreASigningFailureWhenPreparing(): void
    {
        $fixture = new SigningFixture();
        $store = new SwitchableTrustStore($fixture->trustStore);
        $store->failWith(self::unreachableLists());

        try {
            $fixture->signingServiceTrusting($store)->prepare(self::container(), TestPki::signerEc256()->certificate);
            self::fail('a signature was prepared without the trusted lists');
        } catch (SigningException $e) {
            self::assertInstanceOf(TrustedListException::class, $e->getPrevious());
        }
    }

    public function testAPreparedDocumentThatIsNotXmlIsASessionMismatch(): void
    {
        $fixture = new SigningFixture();
        $container = self::container();
        $keyPair = TestPki::signerEc256();
        $prepared = $fixture->signingService->prepare($container, $keyPair->certificate);
        $broken = new DataToBeSigned(
            $prepared->signatureId,
            $prepared->signatureFileName,
            $prepared->algorithm,
            $prepared->digest,
            $prepared->signedInfoCanonical,
            'not xml',
            $prepared->signerCertificate,
            $prepared->containerFingerprint,
            $prepared->level,
            $prepared->createdAt,
        );

        $this->expectException(SessionMismatchException::class);
        $this->expectExceptionMessage('The prepared signature cannot be read');

        $fixture->signingService->finalize($container, $broken, $keyPair->privateKey->sign($prepared->algorithm, $prepared->signedInfoCanonical));
    }

    public function testAnArchiveTimestampThatCannotBeTrustedIsASigningFailure(): void
    {
        $fixture = new SigningFixture();
        $lt = $fixture->signingService->signWith(self::container(), LocalKeySigner::fromKeyPair(TestPki::signerEc256()));
        $fixture->tsa->sign = TestSignatures::sha1(TestKey::fixture('tsa'));

        try {
            $fixture->signingService->archive($lt->container);
            self::fail('an archive timestamp signed with SHA-1 was added');
        } catch (SigningException $e) {
            self::assertStringContainsString('archive timestamp', $e->getMessage());
            self::assertInstanceOf(TimestampVerificationException::class, $e->getPrevious());
        }
    }

    public function testALateOcspResponseIsAWarningNotAFailure(): void
    {
        // A slow signing flow: by the time the OCSP answer is fetched, the
        // timestamp is already sixteen minutes old.
        $fixture = new SigningFixture();
        $fixture->tsa->genTimeOffsetSeconds = -16 * 60;

        $result = $fixture->signingService->signWith(self::container(), LocalKeySigner::fromKeyPair(TestPki::signerEc256()));

        self::assertSame(SignatureLevel::LT, $result->level);
        self::assertCount(1, $result->warnings);
        self::assertStringContainsString('960 seconds after the timestamp', $result->warnings[0]);
    }

    public function testAppendingASecondSignatureToAnExistingContainer(): void
    {
        $fixture = new SigningFixture();
        $container = self::container();

        $first = $fixture->signingService->signWith($container, LocalKeySigner::fromKeyPair(TestPki::signerEc256()));
        $second = $fixture->signingService->signWith($first->container, LocalKeySigner::fromKeyPair(TestPki::signerRsa()));

        self::assertSame('META-INF/signatures1.xml', $second->signatureFileName);
        self::assertCount(2, $second->container->signatureFiles);

        $reread = (new AsicReader())->read((new AsicWriter())->write($second->container));
        self::assertCount(2, $reread->signatureFiles);
        self::assertSame([], $reread->structuralFindings);

        $resolver = new ArrayReferenceResolver(['leping.txt' => "Tere, allkiri!\n"]);
        $verifier = new XmlDsigVerifier();
        foreach ($reread->signatureFiles as $file) {
            $signature = SignatureDocument::parse($file->xml)->signatures()[0];
            self::assertTrue($verifier->verify($signature, $resolver)->isValid(), $file->name);
        }
    }

    public function testMultipleDataFilesEachGetAReferenceAndAFormat(): void
    {
        $fixture = new SigningFixture();
        $container = AsicContainer::create(
            DataFile::fromString('a.txt', 'first'),
            DataFile::fromString('report.pdf', '%PDF-1.4 fake'),
            DataFile::fromString('sub dir/tühi fail.txt', 'unicode and spaces'),
        );

        $result = $fixture->signingService->signWith($container, LocalKeySigner::fromKeyPair(TestPki::signerEc256()));

        $file = $result->container->signatureFile('META-INF/signatures0.xml');
        self::assertNotNull($file);
        $document = SignatureDocument::parse($file->xml);
        $parsed = (new XadesSignatureParser())->parse($document->signatures()[0]);

        self::assertCount(3, $parsed->dataReferences());
        self::assertCount(3, $parsed->dataObjectFormats);
        self::assertSame(['application/pdf'], array_values(array_filter(array_column($parsed->dataObjectFormats, 'mimeType'), static fn(string $m): bool => $m === 'application/pdf')));
        foreach ($parsed->dataReferences() as $reference) {
            self::assertNotNull($parsed->mimeTypeForReference($reference['id']), $reference['uri']);
        }

        $resolver = new ArrayReferenceResolver([
            'a.txt' => 'first',
            'report.pdf' => '%PDF-1.4 fake',
            'sub dir/tühi fail.txt' => 'unicode and spaces',
        ]);
        $verification = (new XmlDsigVerifier())->verify($document->signatures()[0], $resolver);
        self::assertTrue($verification->isValid(), 'percent-encoded names resolve back to their files');
    }

    /**
     * @return list<string> the local names of the unsigned properties, in document order
     */
    private static function elementOrder(SignatureDocument $document, string $signatureId): array
    {
        $signature = $document->signature($signatureId);
        self::assertNotNull($signature);
        $unsigned = \Allkiri\Xades\Dsig\Xml::element(
            $document->xpath(),
            'ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties',
            $signature,
        );
        self::assertNotNull($unsigned);
        $names = [];
        foreach ($unsigned->childNodes as $child) {
            if ($child instanceof \DOMElement && $child->localName !== null) {
                $names[] = $child->localName;
            }
        }

        return $names;
    }
}
