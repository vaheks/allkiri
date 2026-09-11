<?php

declare(strict_types=1);

namespace Allkiri\Validation\Report;

/**
 * The verdict on a signature, in the vocabulary of ETSI EN 319 102-1 that
 * SiVa and DigiDoc4 also report.
 */
enum Indication: string
{
    /** The signature is valid. */
    case TotalPassed = 'TOTAL-PASSED';

    /** The signature is broken, forged, or made with a revoked certificate. */
    case TotalFailed = 'TOTAL-FAILED';

    /** Nothing is provably wrong, but something needed to decide is missing. */
    case Indeterminate = 'INDETERMINATE';

    /**
     * The worse of two verdicts, so a signature is only as good as its weakest part.
     */
    public function worse(self $other): self
    {
        return $this->severity() >= $other->severity() ? $this : $other;
    }

    private function severity(): int
    {
        return match ($this) {
            self::TotalPassed => 0,
            self::Indeterminate => 1,
            self::TotalFailed => 2,
        };
    }
}
