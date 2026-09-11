<?php

declare(strict_types=1);

namespace Allkiri\Trust\TrustedList;

use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustAnchor;

/**
 * A parsed ETSI TS 119 612 trusted list: the services it publishes as trust
 * anchors, plus the pointers a list of lists carries to other lists.
 */
final readonly class TrustedList
{
    /**
     * @param list<TrustAnchor>    $anchors
     * @param list<TrustedListPointer> $pointers non-empty only for a list of trusted lists
     */
    public function __construct(
        public string $territory,
        public string $schemeOperatorName,
        public int $sequenceNumber,
        public ?\DateTimeImmutable $issueDate,
        public ?\DateTimeImmutable $nextUpdate,
        public array $anchors,
        public array $pointers = [],
    ) {}

    /**
     * @param list<ServiceType>|null $types
     *
     * @return list<TrustAnchor>
     */
    public function anchors(?array $types = null): array
    {
        if ($types === null) {
            return $this->anchors;
        }

        return array_values(array_filter($this->anchors, static fn(TrustAnchor $a): bool => \in_array($a->serviceType, $types, true)));
    }

    public function isExpiredAt(\DateTimeInterface $time): bool
    {
        return $this->nextUpdate !== null && $this->nextUpdate < $time;
    }

    /**
     * The pointer to another territory's list, if this is a list of lists.
     */
    public function pointerTo(string $territory): ?TrustedListPointer
    {
        foreach ($this->pointers as $pointer) {
            if ($pointer->territory === $territory) {
                return $pointer;
            }
        }

        return null;
    }
}
