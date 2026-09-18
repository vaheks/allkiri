<?php

declare(strict_types=1);

namespace Allkiri\Trust;

use Allkiri\Trust\TrustedList\ListOfListsSource;
use Allkiri\Trust\TrustedList\TrustedListException;
use Allkiri\Trust\TrustedList\TrustedListLoader;
use Allkiri\Trust\TrustedList\TrustedListStatus;
use Psr\Log\LoggerInterface;

/**
 * Trust anchors reached through the European list of trusted lists.
 *
 * This is how trust is meant to work in production. Only the certificates that
 * sign the list of lists are shipped with the library, and those are published
 * in the Official Journal; everything else — which national lists exist, where
 * they live, which certificates may sign them, and which services each one
 * publishes — is read from the list itself. A national list can change its
 * signing certificate without this library needing a release.
 *
 * Each step verifies the next. The list of lists is verified against the
 * shipped certificates, or those the pivot lists introduced since, and a
 * territory's list only against the certificates the verified list of lists
 * named for it. A list whose signature does not verify is refused rather than
 * used.
 */
final class ListOfListsTrustStore implements TrustStore
{
    private ?InMemoryTrustStore $loaded = null;

    /**
     * @param list<ServiceType>|null $serviceTypes which services to keep as anchors
     */
    public function __construct(
        private readonly TrustedListLoader $loader,
        private readonly ListOfListsSource $source,
        private readonly ?array $serviceTypes = null,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    /**
     * Walk the chain: the list of lists, then each territory's own list.
     *
     * @throws TrustedListException when the list of lists cannot be had, or a
     *                              named territory has no usable list
     */
    public function load(): void
    {
        if ($this->loaded !== null) {
            return;
        }

        $listOfListsSource = $this->source->toSource($this->currentSigners());
        $listOfLists = $this->loader->load($listOfListsSource);
        // Anchors reached through the list of lists rest on it being current too.
        $listOfListsStatus = TrustedListStatus::of($listOfLists, $listOfListsSource->label());
        $this->logger?->info('Loaded the list of trusted lists: sequence {sequence}, {pointers} pointers', [
            'sequence' => $listOfLists->sequenceNumber,
            'pointers' => \count($listOfLists->pointers),
        ]);

        $anchors = [];
        foreach ($this->source->territories as $territory) {
            $pointer = $listOfLists->pointerTo($territory);
            if ($pointer === null) {
                throw new TrustedListException(
                    TrustedListException::REASON_NO_SUCH_LIST,
                    \sprintf('The list of trusted lists has no machine-readable list for %s', $territory),
                );
            }

            $nationalSource = $this->source->sourceFor($pointer, $this->serviceTypes);
            $list = $this->loader->load($nationalSource);
            foreach ($list->anchors($this->serviceTypes) as $anchor) {
                $anchors[] = $anchor->withTrustedList(($anchor->trustedList ?? TrustedListStatus::of($list, $nationalSource->label()))->withListOfLists($listOfListsStatus));
            }
            $this->logger?->info('Loaded the {territory} trusted list: {anchors} anchors', [
                'territory' => $territory,
                'anchors' => \count($list->anchors($this->serviceTypes)),
            ]);
        }

        if ($anchors === []) {
            throw new TrustedListException(
                TrustedListException::REASON_NO_ANCHORS,
                'The trusted lists named no services of the requested kinds',
            );
        }

        $this->loaded = new InMemoryTrustStore($anchors);
    }

    public function anchors(?array $types = null): array
    {
        return $this->store()->anchors($types);
    }

    /**
     * The certificates that may sign the list of lists now.
     *
     * The shipped ones come from an Official Journal publication. The
     * Commission changes them by publishing a pivot list, whose entry for the
     * list of lists names the new set and which is signed with a certificate
     * the set before trusted, and names each pivot, newest first, above that
     * publication in the list's SchemeInformationURI. Following the pivots
     * newer than the shipped publication, oldest first, each verified against
     * the set the one before gave, ends at the current set. That is the
     * procedure the Commission describes, and the one DSS follows.
     *
     * The list is read for this before it is trusted, and nothing in it can
     * widen trust: a pivot counts only when a certificate trusted so far signed
     * it, and the list itself is then verified against the set reached. A pivot
     * that cannot be fetched or verified is skipped, as DSS skips it, and the
     * set stays as it was.
     *
     *
     * @throws TrustedListException when the list of lists cannot be fetched or parsed
     * @return list<\Allkiri\Crypto\Certificate>
     */
    private function currentSigners(): array
    {
        $signers = $this->source->allowedSigners;
        $journal = $this->source->officialJournalUrl;
        if ($journal === null) {
            return $signers;
        }

        $unverified = $this->loader->read($this->source->toSource());
        $pivots = [];
        $journalNamed = false;
        foreach ($unverified->schemeInformationUris as $uri) {
            if ($uri === $journal) {
                $journalNamed = true;
                break;
            }
            if (str_ends_with($uri, '.xml')) {
                $pivots[] = $uri;
            }
        }
        if (!$journalNamed) {
            // After a new publication the Commission leaves the old one listed
            // for a transition period, then drops it with the pivots before it.
            $this->logger?->warning('The list of trusted lists no longer names {journal}, the Official Journal publication the shipped certificates come from; a release with the new publication is due. Every pivot list it names is tried instead.', [
                'journal' => $journal,
            ]);
        }
        // Each one is fetched on the word of a list nothing has verified yet.
        // More than could exist is not a history; it is an attempt to make this
        // server fetch. Trust then stays with the certificates that shipped,
        // which is where it started.
        if (\count($pivots) > ListOfListsSource::MAX_PIVOTS) {
            $this->logger?->warning('The list of trusted lists names {count} pivot lists, more than the {limit} that could plausibly exist; none is followed, and the shipped certificates stand.', [
                'count' => \count($pivots),
                'limit' => ListOfListsSource::MAX_PIVOTS,
            ]);

            return $signers;
        }

        $location = null;
        foreach (array_reverse($pivots) as $url) {
            try {
                $pivot = $this->loader->load($this->source->pivotSource($url, $signers));
            } catch (TrustedListException $exception) {
                $this->logger?->warning('Skipped the pivot list {pivot}: {reason}', ['pivot' => $url, 'reason' => $exception->getMessage()]);
                continue;
            }
            $pointer = $pivot->pointerTo($pivot->territory);
            if ($pointer === null || $pointer->signingCertificates === []) {
                $this->logger?->warning('Skipped the pivot list {pivot}: it names no certificates for the list of lists', ['pivot' => $url]);
                continue;
            }
            $signers = $pointer->signingCertificates;
            $location = $pointer->location;
            $this->logger?->info('Followed the pivot list {pivot}: {certificates} certificates may sign the list of lists', [
                'pivot' => $url,
                'certificates' => \count($signers),
            ]);
        }

        if ($location !== null && $location !== $this->source->url) {
            $this->logger?->warning('The newest pivot list places the list of trusted lists at {location}, but it is read from {configured}; the Commission keeps the old address for a transition period only', [
                'location' => $location,
                'configured' => $this->source->url,
            ]);
        }

        return $signers;
    }

    public function findAnchor(\Allkiri\Crypto\Certificate $certificate): ?TrustAnchor
    {
        return $this->store()->findAnchor($certificate);
    }

    public function findIssuerAnchors(\Allkiri\Crypto\Certificate $subject): array
    {
        return $this->store()->findIssuerAnchors($subject);
    }

    private function store(): InMemoryTrustStore
    {
        $this->load();
        \assert($this->loaded !== null);

        return $this->loaded;
    }
}
