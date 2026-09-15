<?php

declare(strict_types=1);

namespace Allkiri\Trust;

use Allkiri\Crypto\Certificate;

/**
 * Another store, without the anchors of trusted lists that were past their
 * next update by more than a grace period at a given time.
 *
 * Anchors configured by hand have no list and are always kept, and so is a
 * current anchor for a certificate that an expired list also carries.
 */
final class WithoutExpiredListsTrustStore implements TrustStore
{
    public function __construct(
        private readonly TrustStore $inner,
        private readonly \DateTimeInterface $at,
        private readonly int $graceSeconds,
    ) {}

    public function keeps(TrustAnchor $anchor): bool
    {
        return $anchor->trustedList?->expiredAt($this->at, $this->graceSeconds) === null;
    }

    public function anchors(?array $types = null): array
    {
        return array_values(array_filter($this->inner->anchors($types), $this->keeps(...)));
    }

    public function findAnchor(Certificate $certificate): ?TrustAnchor
    {
        // Searched among the kept anchors rather than asked of the inner store,
        // which could answer with a refused anchor and hide a kept one.
        foreach ($this->anchors() as $anchor) {
            if ($anchor->certificate->equals($certificate)) {
                return $anchor;
            }
        }

        return null;
    }

    public function findIssuerAnchors(Certificate $subject): array
    {
        return array_values(array_filter($this->inner->findIssuerAnchors($subject), $this->keeps(...)));
    }
}
