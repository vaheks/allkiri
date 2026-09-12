<?php

declare(strict_types=1);

namespace Allkiri\Trust;

use Allkiri\Trust\TrustedList\ListOfListsSource;
use Allkiri\Trust\TrustedList\TrustedListException;
use Allkiri\Trust\TrustedList\TrustedListLoader;
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
 * shipped certificates, and a territory's list only against the certificates
 * the verified list of lists named for it. A list whose signature does not
 * verify is refused rather than used.
 */
final class ListOfListsTrustStore implements TrustStore
{
    private ?InMemoryTrustStore $loaded = null;

    /** @var list<string> */
    private array $warnings = [];

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

        $listOfLists = $this->loader->load($this->source->toSource());
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

            $list = $this->loader->load($this->source->sourceFor($pointer, $this->serviceTypes));
            foreach ($list->anchors($this->serviceTypes) as $anchor) {
                $anchors[] = $anchor;
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

    /**
     * Anything noticed while loading that did not stop it.
     *
     * @return list<string>
     */
    public function warnings(): array
    {
        return $this->warnings;
    }

    public function anchors(?array $types = null): array
    {
        return $this->store()->anchors($types);
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
