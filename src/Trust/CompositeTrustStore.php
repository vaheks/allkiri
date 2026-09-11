<?php

declare(strict_types=1);

namespace Allkiri\Trust;

use Allkiri\Crypto\Certificate;

/**
 * Several stores queried in order, e.g. a trusted list plus manual extras.
 */
final class CompositeTrustStore implements TrustStore
{
    /** @var list<TrustStore> */
    private readonly array $stores;

    public function __construct(TrustStore ...$stores)
    {
        $this->stores = array_values($stores);
    }

    public function anchors(?array $types = null): array
    {
        $anchors = [];
        foreach ($this->stores as $store) {
            foreach ($store->anchors($types) as $anchor) {
                $anchors[] = $anchor;
            }
        }

        return $anchors;
    }

    public function findAnchor(Certificate $certificate): ?TrustAnchor
    {
        foreach ($this->stores as $store) {
            $anchor = $store->findAnchor($certificate);
            if ($anchor !== null) {
                return $anchor;
            }
        }

        return null;
    }

    public function findIssuerAnchors(Certificate $subject): array
    {
        $anchors = [];
        foreach ($this->stores as $store) {
            foreach ($store->findIssuerAnchors($subject) as $anchor) {
                $anchors[] = $anchor;
            }
        }

        return $anchors;
    }
}
