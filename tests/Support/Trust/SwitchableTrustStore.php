<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Trust;

use Allkiri\Crypto\Certificate;
use Allkiri\Trust\TrustAnchor;
use Allkiri\Trust\TrustedList\TrustedListException;
use Allkiri\Trust\TrustStore;

/**
 * Another store, until a test tells it to fail the way trusted lists that
 * cannot be fetched do.
 */
final class SwitchableTrustStore implements TrustStore
{
    private ?TrustedListException $failure = null;

    public function __construct(private readonly TrustStore $inner) {}

    public function failWith(TrustedListException $failure): void
    {
        $this->failure = $failure;
    }

    public function anchors(?array $types = null): array
    {
        $this->failIfTold();

        return $this->inner->anchors($types);
    }

    public function findAnchor(Certificate $certificate): ?TrustAnchor
    {
        $this->failIfTold();

        return $this->inner->findAnchor($certificate);
    }

    public function findIssuerAnchors(Certificate $subject): array
    {
        $this->failIfTold();

        return $this->inner->findIssuerAnchors($subject);
    }

    private function failIfTold(): void
    {
        if ($this->failure !== null) {
            throw $this->failure;
        }
    }
}
