<?php

declare(strict_types=1);

namespace Allkiri\Validation;

use Allkiri\Container\AsicContainer;
use Allkiri\Container\AsicReader;
use Allkiri\Container\ContainerException;
use Allkiri\Container\StructuralFinding;
use Allkiri\Validation\Report\Finding;
use Allkiri\Validation\Report\Indication;
use Allkiri\Validation\Report\SignatureInfo;
use Allkiri\Validation\Report\SignatureReport;
use Allkiri\Validation\Report\SubIndication;
use Allkiri\Validation\Report\ValidationReport;
use Allkiri\Xades\SignatureDocument;
use Allkiri\Xml\InvalidXmlException;
use Psr\Clock\ClockInterface;

/**
 * Validates a whole container: its structure, then every signature in it.
 *
 * Nothing here throws, for a bad container or for trust anchors that cannot be
 * loaded. A report that says what is wrong is the deliverable, and callers
 * should be able to show it to a user.
 */
final class ContainerValidator
{
    public function __construct(
        private readonly SignatureValidator $signatureValidator,
        private readonly ClockInterface $clock,
        private readonly ValidationPolicy $policy = new ValidationPolicy(),
        private readonly AsicReader $reader = new AsicReader(),
    ) {}

    /**
     * Validate a container held in memory.
     *
     * @param string            $filename the name the report carries; nothing is read from it
     * @param ValidationOptions $options  the moment to validate at, and a trust store to use instead of the validator's own
     */
    public function validate(string $bytes, string $filename = 'document.asice', ValidationOptions $options = new ValidationOptions()): ValidationReport
    {
        $validationTime = $options->validationTime ?? $this->clock->now();

        try {
            $container = $this->reader->read($bytes);
        } catch (ContainerException $e) {
            return new ValidationReport($filename, $validationTime, $this->policy->name, [], [
                Finding::error(FindingCodes::NOT_A_CONTAINER, $e->getMessage(), Indication::TotalFailed, SubIndication::FormatFailure),
            ]);
        }

        $containerFindings = $this->structuralFindings($container);
        $fatal = array_filter($containerFindings, static fn(Finding $f): bool => $f->indication === Indication::TotalFailed);

        $signatures = [];
        foreach ($container->signatureFiles as $file) {
            try {
                $document = SignatureDocument::parse($file->xml);
            } catch (InvalidXmlException $e) {
                $signatures[] = $this->unreadable($file->name, 'The signature file is not well-formed XML: ' . $e->getMessage());
                continue;
            }
            $elements = $document->signatures();
            if ($elements === []) {
                $signatures[] = $this->unreadable($file->name, 'The signature file contains no signature');
                continue;
            }
            foreach ($elements as $element) {
                $report = $this->signatureValidator->validate($container, $file, $element, $validationTime, $options->trustStore);
                $signatures[] = $fatal === [] ? $report : $this->demote($report, $fatal);
            }
        }

        return new ValidationReport($filename, $validationTime, $this->policy->name, $signatures, $containerFindings);
    }

    /**
     * Validate a container read from a file. A file that cannot be read is
     * reported as `NOT_A_CONTAINER`, not thrown.
     *
     * @param ValidationOptions $options the moment to validate at, and a trust store to use instead of the validator's own
     */
    public function validateFile(string $path, ValidationOptions $options = new ValidationOptions()): ValidationReport
    {
        $bytes = @file_get_contents($path);
        if ($bytes === false) {
            return new ValidationReport(basename($path), $this->clock->now(), $this->policy->name, [], [
                Finding::error(FindingCodes::NOT_A_CONTAINER, \sprintf('Could not read "%s"', $path), Indication::TotalFailed, SubIndication::FormatFailure),
            ]);
        }

        return $this->validate($bytes, basename($path), $options);
    }

    /**
     * @return list<Finding>
     */
    private function structuralFindings(AsicContainer $container): array
    {
        $findings = [];
        foreach ($container->structuralFindings as $structural) {
            $findings[] = match ($structural->code) {
                StructuralFinding::MIMETYPE_MISSING,
                StructuralFinding::MIMETYPE_NOT_FIRST,
                StructuralFinding::MIMETYPE_COMPRESSED,
                StructuralFinding::MIMETYPE_HAS_EXTRA_FIELD,
                StructuralFinding::MIMETYPE_WRONG_CONTENT => Finding::error(FindingCodes::MIMETYPE_INVALID, $structural->message, Indication::TotalFailed, SubIndication::FormatFailure),
                StructuralFinding::MANIFEST_MISSING,
                StructuralFinding::MANIFEST_ENTRY_MISSING_FILE,
                StructuralFinding::MANIFEST_DUPLICATE_ENTRY,
                StructuralFinding::FILE_MISSING_MANIFEST_ENTRY => Finding::error(FindingCodes::MANIFEST_MISMATCH, $structural->message, Indication::TotalFailed, SubIndication::FormatFailure),
                StructuralFinding::NO_SIGNATURE_FILES => Finding::error(FindingCodes::NO_SIGNATURES, $structural->message, Indication::TotalFailed, SubIndication::FormatFailure),
                StructuralFinding::NO_DATA_FILES => Finding::error(FindingCodes::MANIFEST_MISMATCH, $structural->message, Indication::TotalFailed, SubIndication::FormatFailure),
                default => Finding::warning(FindingCodes::SIGNATURE_FILE_MALFORMED, $structural->message),
            };
        }

        return $findings;
    }

    /**
     * A signature cannot be better than the container it sits in.
     *
     * @param array<int, Finding> $containerErrors
     */
    private function demote(SignatureReport $report, array $containerErrors): SignatureReport
    {
        $first = array_values($containerErrors)[0];

        return new SignatureReport(
            $report->id,
            $report->signatureFileName,
            Indication::TotalFailed,
            $report->subIndication ?? $first->subIndication,
            $report->format,
            $report->signatureMethod,
            [...$report->findings, ...array_values($containerErrors)],
            $report->info,
            $report->scopes,
            $report->signingCertificate,
        );
    }

    private function unreadable(string $fileName, string $message): SignatureReport
    {
        return new SignatureReport(
            '',
            $fileName,
            Indication::TotalFailed,
            SubIndication::FormatFailure,
            null,
            '',
            [Finding::error(FindingCodes::SIGNATURE_FILE_MALFORMED, $message, Indication::TotalFailed, SubIndication::FormatFailure)],
            new SignatureInfo(),
        );
    }
}
