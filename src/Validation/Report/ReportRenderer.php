<?php

declare(strict_types=1);

namespace Allkiri\Validation\Report;

/**
 * A validation report as something a person can read.
 *
 * The report itself is built for programs: stable codes, ETSI indications, a
 * JSON shape that mirrors SiVa's. None of that helps whoever has to work out
 * why a contract was rejected. This turns it into lines meant for a log, a
 * support ticket or a console.
 *
 * Nothing here is part of the verdict. Rendering never changes what the report
 * says, and an application that shows its own wording should read the findings
 * rather than parse these lines.
 */
final class ReportRenderer
{
    private function __construct() {}

    /**
     * The whole report, a few lines per signature.
     */
    public static function text(ValidationReport $report): string
    {
        $lines = [];

        $lines[] = \sprintf(
            '%s: %d signature%s, %d valid',
            $report->isValid() ? 'VALID' : 'NOT VALID',
            $report->signaturesCount(),
            $report->signaturesCount() === 1 ? '' : 's',
            $report->validSignaturesCount(),
        );

        foreach ($report->containerFindings as $finding) {
            $lines[] = '  container: ' . self::finding($finding);
        }

        foreach ($report->signatures as $index => $signature) {
            $lines[] = '';
            $lines[] = self::heading($signature, $index + 1);
            foreach (self::details($signature) as $detail) {
                $lines[] = '  ' . $detail;
            }
            foreach ($signature->findings as $finding) {
                $lines[] = '  ' . self::finding($finding);
            }
        }

        return implode("\n", $lines) . "\n";
    }

    /**
     * One line saying whether the thing is signed properly, for a log.
     */
    public static function summary(ValidationReport $report): string
    {
        if ($report->signaturesCount() === 0) {
            return 'No signatures';
        }

        $names = [];
        foreach ($report->signatures as $signature) {
            $names[] = $signature->signedBy() ?? 'an unnamed signer';
        }

        return \sprintf(
            '%s: signed by %s',
            $report->isValid() ? 'Valid' : 'Not valid',
            implode(', ', $names),
        );
    }

    private static function heading(SignatureReport $signature, int $number): string
    {
        return \sprintf(
            'Signature %d (%s) %s%s — %s, %s',
            $number,
            $signature->signatureFileName,
            $signature->indication->value,
            $signature->subIndication === null ? '' : '/' . $signature->subIndication->value,
            $signature->signedBy() ?? 'unnamed signer',
            $signature->format === null ? 'unknown level' : $signature->format->value,
        );
    }

    /**
     * @return list<string>
     */
    private static function details(SignatureReport $signature): array
    {
        $details = [];
        $info = $signature->info;

        if ($info->bestSignatureTime !== null) {
            $details[] = 'signed at ' . $info->bestSignatureTime->format(DATE_ATOM)
                . ($info->timestampCreationTime === null ? ' (claimed by the signer, not proven)' : ' (proven by a timestamp)');
        }
        if ($info->ocspResponseCreationTime !== null) {
            $details[] = 'revocation checked at ' . $info->ocspResponseCreationTime->format(DATE_ATOM);
        }
        if ($info->archiveTimestampTime !== null) {
            $details[] = 'archived at ' . $info->archiveTimestampTime->format(DATE_ATOM);
        }
        if ($signature->scopes !== []) {
            $names = array_map(static fn(SignatureScope $scope): string => $scope->name, $signature->scopes);
            $details[] = 'covers ' . implode(', ', $names);
        }
        if ($signature->info->signerRoles !== []) {
            $details[] = 'claimed role: ' . implode(', ', $signature->info->signerRoles);
        }

        return $details;
    }

    private static function finding(Finding $finding): string
    {
        $label = match ($finding->severity) {
            Severity::Error => 'ERROR  ',
            Severity::Warning => 'warning',
            Severity::Info => 'info   ',
        };

        return \sprintf('%s [%s] %s', $label, $finding->code, $finding->message);
    }
}
