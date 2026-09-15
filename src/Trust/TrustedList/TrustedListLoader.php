<?php

declare(strict_types=1);

namespace Allkiri\Trust\TrustedList;

use Allkiri\Http\HttpClient;
use Allkiri\Http\HttpRequest;
use Allkiri\Http\TransportException;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException as CacheInvalidArgumentException;

/**
 * Fetches a trusted list, verifies its signature and parses it, caching the
 * XML so a run does not re-download a megabyte of trust anchors.
 *
 * The cache holds the verified XML rather than parsed objects, so a cache hit
 * is still re-verified: a poisoned cache cannot introduce a trust anchor.
 */
final class TrustedListLoader
{
    public function __construct(
        private readonly HttpClient $http,
        private readonly ?CacheInterface $cache = null,
        private readonly TrustedListParser $parser = new TrustedListParser(),
        private readonly TrustedListVerifier $verifier = new TrustedListVerifier(),
        private readonly ?ClockInterface $clock = null,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    /**
     * @throws TrustedListException
     */
    public function load(TrustedListSource $source): TrustedList
    {
        $cached = $this->cached($source);
        $xml = $cached ?? $this->fetch($source);
        $this->verifier->verify($xml, $source->allowedSigners);
        $list = $this->parser->parse($xml, $source->label());
        // Stored when fetched, not again on every hit. Storing it again would
        // renew the entry's lifetime each time, and under steady use a list past
        // its next update would never be fetched again.
        if ($cached === null) {
            $this->store($source, $xml);
        }

        $now = $this->clock?->now();
        if ($now !== null && $list->isExpiredAt($now)) {
            $this->logger?->warning('Trusted list {list} expired on {nextUpdate}; its anchors are still loaded, and validation reports each signature that rests on them', [
                'list' => $source->label(),
                'nextUpdate' => $list->nextUpdate?->format(DATE_ATOM) ?? 'an unknown date',
            ]);
        }

        return $list;
    }

    /**
     * @throws TrustedListException
     */
    private function fetch(TrustedListSource $source): string
    {
        try {
            $response = $this->http->send(HttpRequest::get($source->url, ['Accept' => 'application/xml, text/xml, */*']));
        } catch (TransportException $e) {
            throw new TrustedListException(TrustedListException::REASON_TRANSPORT, \sprintf('Could not fetch the trusted list %s: %s', HttpRequest::withoutIdentities($source->url), $e->getMessage()), $e);
        }
        if (!$response->isSuccess() || $response->body === '') {
            throw new TrustedListException(TrustedListException::REASON_TRANSPORT, \sprintf('Trusted list %s answered HTTP %d', HttpRequest::withoutIdentities($source->url), $response->status));
        }

        return $response->body;
    }

    private function cached(TrustedListSource $source): ?string
    {
        try {
            $cached = $this->cache?->get($source->cacheKey());
        } catch (CacheInvalidArgumentException) {
            return null;
        }

        return \is_string($cached) && $cached !== '' ? $cached : null;
    }

    private function store(TrustedListSource $source, string $xml): void
    {
        try {
            $this->cache?->set($source->cacheKey(), $xml, $source->cacheTtlSeconds);
        } catch (CacheInvalidArgumentException) {
            // an unusable cache must never stop a signature from being made
        }
    }
}
