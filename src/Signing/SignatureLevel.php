<?php

declare(strict_types=1);

namespace Allkiri\Signing;

/**
 * XAdES baseline levels, in the order they are built.
 */
enum SignatureLevel: string
{
    /** Signature only: no proof of when it was made. */
    case B = 'XAdES_BASELINE_B';

    /** B plus a signature timestamp. */
    case T = 'XAdES_BASELINE_T';

    /** T plus the certificates and revocation data needed to validate it later. */
    case LT = 'XAdES_BASELINE_LT';

    /** LT plus an archive timestamp (Phase 5). */
    case LTA = 'XAdES_BASELINE_LTA';

    public function includes(self $other): bool
    {
        return $this->rank() >= $other->rank();
    }

    public function rank(): int
    {
        return match ($this) {
            self::B => 0,
            self::T => 1,
            self::LT => 2,
            self::LTA => 3,
        };
    }
}
