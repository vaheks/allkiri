<?php

declare(strict_types=1);

namespace Allkiri\Trust;

use Allkiri\Crypto\Certificate;

/**
 * Where trust anchors come from: a parsed trusted list, manual configuration,
 * or a combination.
 */
interface TrustStore
{
    /**
     * @param list<ServiceType>|null $types restrict to these service types; null for all
     *
     * @return list<TrustAnchor>
     */
    public function anchors(?array $types = null): array;

    /**
     * The anchor whose certificate is exactly this one, if any.
     */
    public function findAnchor(Certificate $certificate): ?TrustAnchor;

    /**
     * Anchors whose certificate could have issued the subject: same subject
     * name as the subject's issuer, and matching key identifiers when both sides have them.
     *
     * @return list<TrustAnchor>
     */
    public function findIssuerAnchors(Certificate $subject): array;
}
