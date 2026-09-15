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
 */
final readonly class ListOfListsSource
{
    public const EU_URL = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml';

    /**
     * @param list<Certificate> $allowedSigners the certificates the Official Journal publishes
     * @param list<string>      $territories    two-letter codes to follow, in order
     */
    public function __construct(
        public string $url,
        public array $allowedSigners,
        public array $territories,
        public string $name = 'EU list of trusted lists',
        public int $cacheTtlSeconds = 86400,
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
     */
    public function toSource(): TrustedListSource
    {
        return new TrustedListSource($this->url, $this->allowedSigners, null, $this->name, $this->cacheTtlSeconds);
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
