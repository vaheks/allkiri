<?php

declare(strict_types=1);

namespace Allkiri\Validation\Siva;

use Allkiri\Validation\Report\SignatureReport;
use Allkiri\Validation\Report\ValidationReport;

/**
 * What allkiri says about a container next to what RIA's SiVa says.
 *
 * Two validators disagreeing is worth knowing about, and which of them is right
 * is not something a library can decide: SiVa is the reference for Estonian
 * practice, but it is a remote service with its own policy, its own trust list
 * refresh cycle and its own idea of the current time. A difference is a
 * question, not a verdict.
 *
 * This is a diagnostic. Nothing in the library's own validation consults it,
 * and no application should make SiVa's answer a condition of accepting a
 * signature without deciding deliberately that it wants that dependency.
 */
final readonly class SivaComparison
{
    /**
     * @param list<string> $differences one line each, empty when the two agree
     */
    public function __construct(
        public ValidationReport $ours,
        public SivaReport $theirs,
        public array $differences,
    ) {}

    public function agrees(): bool
    {
        return $this->differences === [];
    }

    /**
     * Compare the two, signature by signature.
     */
    public static function of(ValidationReport $ours, SivaReport $theirs): self
    {
        $differences = [];

        if ($ours->signaturesCount() !== $theirs->signaturesCount) {
            $differences[] = \sprintf(
                'allkiri found %d signature(s), SiVa found %d',
                $ours->signaturesCount(),
                $theirs->signaturesCount,
            );

            return new self($ours, $theirs, $differences);
        }

        foreach ($ours->signatures as $index => $signature) {
            $sivaSignature = $theirs->signatures[$index] ?? null;
            if ($sivaSignature === null) {
                $differences[] = \sprintf('SiVa said nothing about signature %d', $index + 1);
                continue;
            }
            foreach (self::compareSignature($index + 1, $signature, $sivaSignature) as $difference) {
                $differences[] = $difference;
            }
        }

        return new self($ours, $theirs, $differences);
    }

    /**
     * @return list<string>
     */
    private static function compareSignature(int $number, SignatureReport $ours, SivaSignature $theirs): array
    {
        $differences = [];

        if ($ours->indication->value !== $theirs->indication) {
            $differences[] = \sprintf(
                'signature %d: allkiri says %s, SiVa says %s',
                $number,
                $ours->indication->value,
                $theirs->indication,
            );
        }

        $ourSub = $ours->subIndication?->value;
        if ($ourSub !== $theirs->subIndication && ($ourSub !== null || $theirs->subIndication !== null)) {
            $differences[] = \sprintf(
                'signature %d: allkiri says %s, SiVa says %s',
                $number,
                $ourSub ?? 'no sub-indication',
                $theirs->subIndication ?? 'no sub-indication',
            );
        }

        $ourFormat = $ours->format?->value;
        if ($theirs->signatureFormat !== null && $ourFormat !== $theirs->signatureFormat) {
            $differences[] = \sprintf(
                'signature %d: allkiri reads it as %s, SiVa as %s',
                $number,
                $ourFormat ?? 'an unknown level',
                $theirs->signatureFormat,
            );
        }

        return $differences;
    }

    public function describe(): string
    {
        if ($this->agrees()) {
            return 'allkiri and SiVa agree';
        }

        return "allkiri and SiVa disagree:\n  " . implode("\n  ", $this->differences);
    }
}
