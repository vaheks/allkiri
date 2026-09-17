<?php

declare(strict_types=1);

namespace Allkiri\Trust\TrustedList;

use Allkiri\Crypto\Certificate;
use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Http\HttpRequest;

/**
 * Where to start when trust is taken from the European list of trusted lists
 * rather than from one national list pinned by hand.
 *
 * The chain is: verify the list of lists against certificates the Official
 * Journal publishes, read from it where a territory's own list lives and which
 * certificates may sign that, then verify the national list against those. Only
 * the first step needs anything shipped with the library, and that is the point
 * of the arrangement: national lists and their signing certificates change
 * without anyone having to release a new version.
 *
 * The certificates that sign the list of lists change too. The Commission
 * announces a new set with a pivot list, signed with a certificate the old set
 * trusts, before it publishes the set in the Official Journal. Given the Journal
 * publication its certificates come from, the trust store follows those pivots.
 */
final readonly class ListOfListsSource
{
    public const EU_URL = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml';

    /** A pivot list is an archive that never changes, so it is kept longer than a list that does. */
    public const PIVOT_CACHE_TTL_SECONDS = 30 * 86400;

    /**
     * @param list<Certificate> $allowedSigners     the certificates the Official Journal publishes
     * @param list<string>      $territories        two-letter codes to follow, in order
     * @param string|null       $officialJournalUrl the publication $allowedSigners come from, as the list of
     *                                              lists names it in its SchemeInformationURI; pivot lists
     *                                              newer than it are followed. Null follows none
     */
    public function __construct(
        public string $url,
        public array $allowedSigners,
        public array $territories,
        public string $name = 'EU list of trusted lists',
        public int $cacheTtlSeconds = 86400,
        public ?string $officialJournalUrl = null,
    ) {
        if ($allowedSigners === []) {
            throw new InvalidArgumentException('A list of trusted lists needs the certificates that may sign it; without them anything could claim to be it');
        }
        if ($territories === []) {
            throw new InvalidArgumentException('Name at least one territory whose list should be followed');
        }
        foreach ($territories as $territory) {
            // ISO 3166-1 alpha-2, or a test list's own code such as "EE_T".
            if (preg_match('/^[A-Z]{2}(_[A-Z0-9]+)?$/', $territory) !== 1) {
                throw new InvalidArgumentException(\sprintf(
                    '"%s" is not a territory code such as "EE", or a test list code such as "EE_T"',
                    $territory,
                ));
            }
        }
    }

    /**
     * The source for fetching and verifying the list of lists itself.
     *
     * @param list<Certificate>|null $signers the certificates that may sign it now, as the pivot
     *                                        lists have it; the shipped ones when null
     */
    public function toSource(?array $signers = null): TrustedListSource
    {
        return new TrustedListSource($this->url, $signers ?? $this->allowedSigners, null, $this->name, $this->cacheTtlSeconds);
    }

    /**
     * The source for one pivot list, verified against the certificates trusted
     * before it.
     *
     * @param list<Certificate> $signers
     */
    public function pivotSource(string $url, array $signers): TrustedListSource
    {
        if (!HttpRequest::isHttpUrl($url)) {
            throw new TrustedListException(
                TrustedListException::REASON_TRANSPORT,
                \sprintf('The list of trusted lists names a pivot list at "%s", which is not an http(s) URL, so it cannot be fetched', HttpRequest::withoutIdentities($url)),
            );
        }

        return new TrustedListSource($url, $signers, null, 'pivot list ' . basename((string) parse_url($url, PHP_URL_PATH)), self::PIVOT_CACHE_TTL_SECONDS);
    }

    /**
     * The source for one territory's list, with the signers the list of lists
     * named for it.
     *
     * @param list<\Allkiri\Trust\ServiceType>|null $serviceTypes
     */
    public function sourceFor(TrustedListPointer $pointer, ?array $serviceTypes = null): TrustedListSource
    {
        if ($pointer->signingCertificates === []) {
            throw new TrustedListException(
                TrustedListException::REASON_NO_PINS,
                \sprintf('The list of trusted lists names no signing certificate for %s, so its list cannot be verified', $pointer->territory),
            );
        }
        if (!HttpRequest::isHttpUrl($pointer->location)) {
            throw new TrustedListException(
                TrustedListException::REASON_NO_SUCH_LIST,
                \sprintf('The list of trusted lists places the list for %s at "%s", which is not an http(s) URL, so it cannot be fetched', $pointer->territory, HttpRequest::withoutIdentities($pointer->location)),
            );
        }

        return new TrustedListSource(
            $pointer->location,
            $pointer->signingCertificates,
            $serviceTypes,
            $pointer->territory . ' trusted list',
            $this->cacheTtlSeconds,
        );
    }
}
