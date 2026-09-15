<?php

declare(strict_types=1);

namespace Allkiri\Trust;

use Allkiri\Crypto\Certificate;
use Allkiri\Trust\TrustedList\TrustedList;
use Allkiri\Trust\TrustedList\TrustedListException;
use Allkiri\Trust\TrustedList\TrustedListLoader;
use Allkiri\Trust\TrustedList\TrustedListSource;
use Allkiri\Trust\TrustedList\TrustedListStatus;

/**
 * Anchors from one or more trusted lists, loaded on first use.
 */
final class TrustedListTrustStore implements TrustStore
{
    /** @var list<TrustedListSource> */
    private readonly array $sources;

    private ?InMemoryTrustStore $loaded = null;

    /**
     * @param list<TrustedListSource> $sources
     */
    public function __construct(
        private readonly TrustedListLoader $loader,
        array $sources,
    ) {
        $this->sources = $sources;
    }

    /**
     * The lists are fetched, verified and parsed here; every caller after the
     * first reuses the result.
     *
     * @throws TrustedListException
     */
    public function load(): void
    {
        if ($this->loaded !== null) {
            return;
        }
        $anchors = [];
        foreach ($this->sources as $source) {
            $list = $this->loader->load($source);
            foreach ($list->anchors($source->serviceTypes) as $anchor) {
                $anchors[] = $anchor;
            }
        }
        $this->loaded = new InMemoryTrustStore($anchors);
    }

    /**
     * Use already-parsed lists instead of fetching them.
     *
     * @param list<TrustedList> $lists
     */
    public static function fromLists(array $lists, TrustedListLoader $loader): self
    {
        $store = new self($loader, []);
        $anchors = [];
        foreach ($lists as $list) {
            foreach ($list->anchors() as $anchor) {
                // A list built in code has no parser to stamp its anchors.
                $anchors[] = $anchor->trustedList === null ? $anchor->withTrustedList(TrustedListStatus::of($list, $list->territory)) : $anchor;
            }
        }
        $store->loaded = new InMemoryTrustStore($anchors);

        return $store;
    }

    public function anchors(?array $types = null): array
    {
        return $this->store()->anchors($types);
    }

    public function findAnchor(Certificate $certificate): ?TrustAnchor
    {
        return $this->store()->findAnchor($certificate);
    }

    public function findIssuerAnchors(Certificate $subject): array
    {
        return $this->store()->findIssuerAnchors($subject);
    }

    private function store(): InMemoryTrustStore
    {
        $this->load();

        return $this->loaded ?? new InMemoryTrustStore([]);
    }
}
