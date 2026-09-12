<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Validation;

use Allkiri\Container\AsicContainer;
use Allkiri\Container\AsicWriter;
use Allkiri\Container\DataFile;
use Allkiri\Signing\LocalKeySigner;
use Allkiri\Signing\SignatureLevel;
use Allkiri\Signing\SigningOptions;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Tests\Support\SigningFixture;
use Allkiri\Validation\ContainerValidator;
use Allkiri\Validation\Report\Indication;
use Allkiri\Validation\Report\ReportRenderer;
use Allkiri\Validation\Report\SubIndication;
use Allkiri\Validation\Report\ValidationReport;
use Allkiri\Validation\SignatureValidator;
use Allkiri\Validation\Siva\SivaComparison;
use Allkiri\Validation\Siva\SivaReport;
use Allkiri\Validation\Siva\SivaSignature;
use Allkiri\Validation\ValidationPolicy;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class ReportHelpersTest extends TestCase
{
    private SigningFixture $fixture;

    protected function setUp(): void
    {
        $this->fixture = new SigningFixture();
    }

    private function report(SignatureLevel $level = SignatureLevel::LT): ValidationReport
    {
        $result = $this->fixture->signingService->signWith(
            AsicContainer::create(DataFile::fromString('leping.txt', "Tere!\n")),
            LocalKeySigner::fromKeyPair(TestPki::signerEc256()),
            new SigningOptions($level),
        );

        $policy = new ValidationPolicy();
        $validator = new ContainerValidator(
            new SignatureValidator($this->fixture->trustStore, $policy),
            $this->fixture->clock,
            $policy,
        );

        return $validator->validate((new AsicWriter())->write($result->container), 'leping.asice');
    }

    // --- rendering ----------------------------------------------------------

    public function testTheTextSaysWhetherItIsValidAndWhoSignedIt(): void
    {
        $text = ReportRenderer::text($this->report());

        self::assertStringStartsWith('VALID: 1 signature, 1 valid', $text);
        self::assertStringContainsString('TOTAL-PASSED', $text);
        self::assertStringContainsString('XAdES_BASELINE_LT', $text);
        self::assertStringContainsString('covers leping.txt', $text);
        self::assertStringContainsString('proven by a timestamp', $text);
        self::assertStringContainsString('revocation checked at', $text);
    }

    public function testAnArchivedSignatureSaysWhenItWasArchived(): void
    {
        $text = ReportRenderer::text($this->report(SignatureLevel::LTA));

        self::assertStringContainsString('archived at', $text);
        self::assertStringContainsString('XAdES_BASELINE_LTA', $text);
    }

    /**
     * A signature with no timestamp rests on a time the signer simply claimed,
     * and the rendering should not let that pass as proven.
     */
    public function testAClaimedSigningTimeIsNotPresentedAsProven(): void
    {
        $result = $this->fixture->besOnlyService()->signWith(
            AsicContainer::create(DataFile::fromString('leping.txt', "Tere!\n")),
            LocalKeySigner::fromKeyPair(TestPki::signerEc256()),
            new SigningOptions(SignatureLevel::B),
        );

        $policy = new ValidationPolicy();
        $validator = new ContainerValidator(new SignatureValidator($this->fixture->trustStore, $policy), $this->fixture->clock, $policy);
        $report = $validator->validate((new AsicWriter())->write($result->container), 'leping.asice');

        $text = ReportRenderer::text($report);

        self::assertStringContainsString('claimed by the signer, not proven', $text);
        self::assertStringNotContainsString('proven by a timestamp', $text);
    }

    public function testTheSummaryIsOneLine(): void
    {
        $summary = ReportRenderer::summary($this->report());

        self::assertStringNotContainsString("\n", $summary);
        self::assertStringStartsWith('Valid: signed by ', $summary);
    }

    public function testAnEmptyReportSaysSo(): void
    {
        $empty = new ValidationReport('empty.asice', new \DateTimeImmutable('2026-03-01T10:00:00Z'), 'POLv4', []);

        self::assertSame('No signatures', ReportRenderer::summary($empty));
        self::assertStringContainsString('NOT VALID: 0 signatures', ReportRenderer::text($empty));
    }

    // --- comparing with SiVa ------------------------------------------------

    private static function siva(string $indication, ?string $subIndication = null, ?string $format = 'XAdES_BASELINE_LT', int $count = 1): SivaReport
    {
        $signatures = [];
        for ($i = 0; $i < $count; ++$i) {
            $signatures[] = new SivaSignature('S0', $indication, $subIndication, $format, 'QESIG', 'Someone', [], []);
        }

        return new SivaReport('POLv4', 'ASiC-E', $count, $indication === 'TOTAL-PASSED' ? $count : 0, $signatures);
    }

    public function testAgreementIsReportedAsAgreement(): void
    {
        $comparison = SivaComparison::of($this->report(), self::siva('TOTAL-PASSED'));

        self::assertTrue($comparison->agrees());
        self::assertSame([], $comparison->differences);
        self::assertSame('allkiri and SiVa agree', $comparison->describe());
    }

    public function testADifferentVerdictIsNamed(): void
    {
        $comparison = SivaComparison::of($this->report(), self::siva('INDETERMINATE', 'NO_CERTIFICATE_CHAIN_FOUND'));

        self::assertFalse($comparison->agrees());
        self::assertStringContainsString('allkiri says TOTAL-PASSED, SiVa says INDETERMINATE', $comparison->describe());
        self::assertStringContainsString('no sub-indication, SiVa says NO_CERTIFICATE_CHAIN_FOUND', $comparison->describe());
    }

    public function testADifferentLevelIsNamed(): void
    {
        $comparison = SivaComparison::of($this->report(), self::siva('TOTAL-PASSED', null, 'XAdES_BASELINE_LTA'));

        self::assertStringContainsString('allkiri reads it as XAdES_BASELINE_LT, SiVa as XAdES_BASELINE_LTA', $comparison->describe());
    }

    /**
     * Counting signatures differently is a bigger disagreement than any verdict
     * on one of them, so it is reported on its own.
     */
    public function testADifferentSignatureCountStopsTheComparison(): void
    {
        $comparison = SivaComparison::of($this->report(), self::siva('TOTAL-PASSED', count: 2));

        self::assertCount(1, $comparison->differences);
        self::assertStringContainsString('allkiri found 1 signature(s), SiVa found 2', $comparison->differences[0]);
    }

    public function testSivaSayingNothingAboutTheLevelIsNotADisagreement(): void
    {
        $comparison = SivaComparison::of($this->report(), self::siva('TOTAL-PASSED', null, null));

        self::assertTrue($comparison->agrees());
    }

    public function testTheVerdictsUseTheSameVocabulary(): void
    {
        // Both sides name indications the same way, which is what makes a
        // comparison meaningful rather than a translation exercise.
        self::assertSame('TOTAL-PASSED', Indication::TotalPassed->value);
        self::assertSame('INDETERMINATE', Indication::Indeterminate->value);
        self::assertSame('TOTAL-FAILED', Indication::TotalFailed->value);
        self::assertSame('NO_CERTIFICATE_CHAIN_FOUND', SubIndication::NoCertificateChainFound->value);
    }
}
