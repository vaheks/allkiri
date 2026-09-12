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
     *
     * A territory usually has two: the machine-processable XML and a
     * human-readable PDF of the same list. The XML is what a program can use,
     * and it is not always the first, so it is preferred explicitly. In the EU
     * list of lists as of September 2026 the Estonian PDF comes first, and
     * following that would fetch a document rather than a list.
     */
    public function pointerTo(string $territory, ?string $mimeType = TrustedListPointer::MIME_XML): ?TrustedListPointer
    {
        $fallback = null;
        foreach ($this->pointers as $pointer) {
            if ($pointer->territory !== $territory) {
                continue;
            }
            if ($mimeType === null || $pointer->mimeType === $mimeType) {
                return $pointer;
            }
            $fallback ??= $pointer;
        }

        // A list that names no MIME type at all is still usable; one of another
        // type is returned only because having something beats having nothing,
        // and the caller can see what it got.
        return $fallback?->mimeType === null ? $fallback : null;
    }

    /**
     * Every pointer for a territory, in the order the list gives them.
     *
     * @return list<TrustedListPointer>
     */
    public function pointersTo(string $territory): array
    {
        return array_values(array_filter(
            $this->pointers,
            static fn(TrustedListPointer $pointer): bool => $pointer->territory === $territory,
        ));
    }
}
