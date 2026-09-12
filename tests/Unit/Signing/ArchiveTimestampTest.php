<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Signing;

use Allkiri\Container\AsicContainer;
use Allkiri\Container\AsicReader;
use Allkiri\Container\AsicWriter;
use Allkiri\Container\DataFile;
use Allkiri\Signing\LocalKeySigner;
use Allkiri\Signing\SignatureLevel;
use Allkiri\Signing\SigningException;
use Allkiri\Signing\SigningOptions;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Tests\Support\SigningFixture;
use Allkiri\Validation\ContainerValidator;
use Allkiri\Validation\FindingCodes;
use Allkiri\Validation\Report\Indication;
use Allkiri\Validation\Report\SignatureReport;
use Allkiri\Validation\SignatureValidator;
use Allkiri\Validation\ValidationPolicy;
use Allkiri\Xades\Dsig\Xml;
use Allkiri\Xades\SignatureDocument;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * Archive timestamps end to end: made offline, then judged by our own
 * validator.
 *
 * The construction itself is checked against a digidoc4j container in
 * `ArchiveTimestampDataTest`; this is about the two halves agreeing, and about
 * what happens when one of them is broken.
 */
#[CoversNothing]
final class ArchiveTimestampTest extends TestCase
{
    private SigningFixture $fixture;

    protected function setUp(): void
    {
        $this->fixture = new SigningFixture();
    }

    private static function container(): AsicContainer
    {
        return AsicContainer::create(DataFile::fromString('leping.txt', "Tere, allkiri!\n"));
    }

    private function signLt(): \Allkiri\Signing\SigningResult
    {
        return $this->fixture->signingService->signWith(
            self::container(),
            LocalKeySigner::fromKeyPair(TestPki::signerEc256()),
        );
    }

    // --- making one ---------------------------------------------------------

    public function testSigningStraightToLtaProducesAnArchiveTimestamp(): void
    {
        $result = $this->fixture->signingService->signWith(
            self::container(),
            LocalKeySigner::fromKeyPair(TestPki::signerEc256()),
            new SigningOptions(SignatureLevel::LTA),
        );

        self::assertSame(SignatureLevel::LTA, $result->level);

        $report = $this->validate($result->container);
        self::assertSame(SignatureLevel::LTA, $report->format);
        self::assertSame(Indication::TotalPassed, $report->indication);
        self::assertNotNull($report->info->archiveTimestampTime);
    }

    /**
     * The usual case: a signature made at LT is archived later, when its
     * existing proof is getting old.
     */
    public function testAnExistingLtSignatureCanBeArchivedAfterwards(): void
    {
        $lt = $this->signLt();
        self::assertSame(SignatureLevel::LT, $lt->level);

        $this->fixture->clock->advance('P400D');
        $archived = $this->fixture->signingService->archive($lt->container);

        self::assertSame(SignatureLevel::LTA, $archived->level);
        $report = $this->validate($archived->container);
        self::assertSame(SignatureLevel::LTA, $report->format);
        self::assertSame(Indication::TotalPassed, $report->indication);
    }

    /**
     * Each archive timestamp covers the ones before it, so a signature can be
     * carried forward indefinitely by stamping it again.
     */
    public function testAnArchiveTimestampCanBeLaidOverAnother(): void
    {
        $result = $this->fixture->signingService->archive($this->signLt()->container);

        $this->fixture->clock->advance('P1000D');
        $again = $this->fixture->signingService->archive($result->container);

        $report = $this->validate($again->container);
        self::assertSame(Indication::TotalPassed, $report->indication);
        self::assertSame([], $report->errors());

        $document = SignatureDocument::parse($again->container->signatureFiles[0]->xml);
        $signature = $document->signatures()[0];
        self::assertCount(2, Xml::elements($document->xpath(), './/xadesv141:ArchiveTimeStamp', $signature));
    }

    public function testTheArchiveTimestampSaysHowItWasCanonicalised(): void
    {
        $result = $this->fixture->signingService->archive($this->signLt()->container);

        $document = SignatureDocument::parse($result->container->signatureFiles[0]->xml);
        $archive = Xml::element($document->xpath(), './/xadesv141:ArchiveTimeStamp', $document->signatures()[0]);
        self::assertNotNull($archive);

        // Leaving this out would mean inclusive canonicalisation by default,
        // and a validator would then reconstruct a different stream.
        $method = Xml::element($document->xpath(), './ds:CanonicalizationMethod', $archive);
        self::assertNotNull($method);
        self::assertSame(\Allkiri\Xades\Ns::C14N_EXC, $method->getAttribute('Algorithm'));
    }

    public function testTheContainerSurvivesBeingWrittenAndReadBack(): void
    {
        $archived = $this->fixture->signingService->archive($this->signLt()->container);

        $bytes = (new AsicWriter())->write($archived->container);
        $reread = (new AsicReader())->read($bytes);

        $report = $this->validate($reread);
        self::assertSame(SignatureLevel::LTA, $report->format);
        self::assertSame(Indication::TotalPassed, $report->indication);
    }

    // --- refusals -----------------------------------------------------------

    public function testASignatureWithoutRevocationDataCannotBeArchived(): void
    {
        $bes = $this->fixture->besOnlyService()->signWith(
            self::container(),
            LocalKeySigner::fromKeyPair(TestPki::signerEc256()),
            new SigningOptions(SignatureLevel::B),
        );

        $this->expectExceptionMessageMatches('/extend to LT first/');

        $this->fixture->signingService->archive($bes->container);
    }

    public function testArchivingNeedsATimestampService(): void
    {
        $lt = $this->signLt();

        $this->expectException(SigningException::class);

        $this->fixture->besOnlyService()->archive($lt->container);
    }

    public function testAskingForASignatureFileThatIsNotThereIsReported(): void
    {
        $lt = $this->signLt();

        $this->expectExceptionMessageMatches('/no signature file/');

        $this->fixture->signingService->archive($lt->container, 'META-INF/signatures9.xml');
    }

    // --- what a broken one looks like ---------------------------------------

    /**
     * Tampering after the archive timestamp is exactly what it exists to catch.
     */
    public function testATamperedDataFileBreaksTheArchiveTimestamp(): void
    {
        $archived = $this->fixture->signingService->archive($this->signLt()->container);

        $tampered = AsicContainer::fromParts(
            [DataFile::fromString('leping.txt', "Tere, vale leping!\n")],
            $archived->container->signatureFiles,
            $archived->container->manifest,
            [],
            [],
        );

        $report = $this->validate($tampered);

        self::assertNotSame(Indication::TotalPassed, $report->indication);
        $codes = array_map(static fn($f): string => $f->code, $report->errors());
        self::assertContains(FindingCodes::ARCHIVE_TIMESTAMP_INVALID, $codes);
    }

    /**
     * A timestamp from an authority nobody trusts proves nothing, and the
     * signature beneath it is still reported on its own merits.
     */
    public function testAnUntrustedArchiveAuthorityIsReported(): void
    {
        $archived = $this->fixture->signingService->archive($this->signLt()->container);

        // A trust store that knows the signer and the responder but not the
        // timestamp authority.
        $store = new \Allkiri\Trust\CompositeTrustStore(
            \Allkiri\Trust\InMemoryTrustStore::fromCertificates([TestPki::ca()->certificate], \Allkiri\Trust\ServiceType::CaQc, 'test PKI'),
            \Allkiri\Trust\InMemoryTrustStore::fromCertificates([TestPki::ocspResponder()->certificate], \Allkiri\Trust\ServiceType::OcspQc, 'test PKI'),
        );

        $policy = new ValidationPolicy();
        $validator = new ContainerValidator(new SignatureValidator($store, $policy), $this->fixture->clock, $policy);
        $report = $validator->validate((new AsicWriter())->write($archived->container), 'leping.asice');

        $codes = array_map(static fn($f): string => $f->code, $report->signatures[0]->errors());
        self::assertContains(FindingCodes::ARCHIVE_TIMESTAMP_NOT_TRUSTED, $codes);
    }

    // --- what other implementations make ------------------------------------

    /**
     * The container digidoc4j produced must validate as LTA now that the
     * archive timestamp is checked rather than merely noticed.
     */
    public function testTheDigidoc4jArchiveTimestampIsVerifiedNotJustReported(): void
    {
        $bytes = (string) file_get_contents(__DIR__ . '/../../fixtures/containers/valid-asice-lta.asice');

        $policy = new ValidationPolicy();
        $validator = new ContainerValidator(
            new SignatureValidator($this->fixture->trustStore, $policy),
            $this->fixture->clock,
            $policy,
        );
        $report = $validator->validate($bytes, 'valid-asice-lta.asice')->signatures[0];

        self::assertSame(SignatureLevel::LTA, $report->format);

        // Its PKI is SK's, which this fixture's store does not carry, so the
        // trust findings are expected. What must not appear is a complaint that
        // the archive timestamp itself does not add up.
        $codes = array_map(static fn($f): string => $f->code, $report->errors());
        self::assertNotContains(FindingCodes::ARCHIVE_TIMESTAMP_INVALID, $codes, implode('; ', array_map(static fn($f): string => $f->code . ': ' . $f->message, $report->errors())));
    }

    private function validate(AsicContainer $container): SignatureReport
    {
        $policy = new ValidationPolicy();
        $validator = new ContainerValidator(
            new SignatureValidator($this->fixture->trustStore, $policy),
            $this->fixture->clock,
            $policy,
        );

        $report = $validator->validate((new AsicWriter())->write($container), 'leping.asice');
        self::assertSame([], $report->containerFindings);

        return $report->signatures[0];
    }
}
