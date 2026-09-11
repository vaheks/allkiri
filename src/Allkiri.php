<?php

declare(strict_types=1);

namespace Allkiri;

use Allkiri\Clock\SystemClock;
use Allkiri\Config\ArrayCache;
use Allkiri\Config\Environment;
use Allkiri\Container\AsicReader;
use Allkiri\Container\AsicWriter;
use Allkiri\Crypto\NonceGenerator;
use Allkiri\Crypto\Ocsp\OcspClient;
use Allkiri\Crypto\Ocsp\OcspVerificationOptions;
use Allkiri\Crypto\RandomNonceGenerator;
use Allkiri\Crypto\Tsp\TspClient;
use Allkiri\Http\CurlHttpClient;
use Allkiri\Http\HttpClient;
use Allkiri\Signing\SigningService;
use Allkiri\Trust\ChainBuilder;
use Allkiri\Trust\CompositeTrustStore;
use Allkiri\Trust\InMemoryTrustStore;
use Allkiri\Trust\TrustedList\TrustedListLoader;
use Allkiri\Trust\TrustedListTrustStore;
use Allkiri\Trust\TrustStore;
use Allkiri\Validation\ContainerValidator;
use Allkiri\Validation\SignatureValidator;
use Allkiri\Validation\ValidationPolicy;
use Allkiri\Xades\LtExtender;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * The short way in: one object that wires the library for an environment.
 *
 * ```php
 * $allkiri = new Allkiri(Environment::demo());
 * $result = $allkiri->signingService()->signWith($container, $signer);
 * $report = $allkiri->validator()->validate($bytes);
 * ```
 *
 * Applications with a dependency injection container can build the same
 * objects themselves; nothing in the library depends on this class.
 */
final class Allkiri
{
    public const VERSION = '0.1.0-dev';

    /** Sent as User-Agent to SK, RIA and Zetes services so operators can identify the client. */
    public const USER_AGENT = 'allkiri/' . self::VERSION . ' (+https://github.com/vaheks/allkiri)';

    private ?TrustStore $trustStore = null;

    private ?SigningService $signingService = null;

    private ?ContainerValidator $validator = null;

    public function __construct(
        private readonly Environment $environment,
        private readonly ?HttpClient $http = null,
        private readonly ClockInterface $clock = new SystemClock(),
        private readonly ?CacheInterface $cache = null,
        private readonly ValidationPolicy $policy = new ValidationPolicy(),
        private readonly NonceGenerator $nonces = new RandomNonceGenerator(),
        private readonly ?LoggerInterface $logger = null,
    ) {}

    public function environment(): Environment
    {
        return $this->environment;
    }

    public function httpClient(): HttpClient
    {
        return $this->http ?? new CurlHttpClient($this->environment->httpTimeoutSeconds);
    }

    /**
     * Trust anchors from the configured trusted lists plus any extra ones.
     */
    public function trustStore(): TrustStore
    {
        if ($this->trustStore === null) {
            $stores = [];
            if ($this->environment->trustedListSources !== []) {
                $stores[] = new TrustedListTrustStore(
                    new TrustedListLoader($this->httpClient(), $this->cache ?? new ArrayCache(), clock: $this->clock, logger: $this->logger),
                    $this->environment->trustedListSources,
                );
            }
            if ($this->environment->extraTrustAnchors !== []) {
                $stores[] = new InMemoryTrustStore($this->environment->extraTrustAnchors);
            }
            $this->trustStore = \count($stores) === 1 ? $stores[0] : new CompositeTrustStore(...$stores);
        }

        return $this->trustStore;
    }

    public function chainBuilder(): ChainBuilder
    {
        return new ChainBuilder($this->trustStore());
    }

    public function tspClient(): TspClient
    {
        return new TspClient($this->httpClient(), $this->environment->tsaUrl, nonces: $this->nonces, hashAlgorithm: $this->environment->timestampDigestAlgorithm);
    }

    public function ocspClient(): OcspClient
    {
        return new OcspClient(
            $this->httpClient(),
            $this->clock,
            nonces: $this->nonces,
            options: new OcspVerificationOptions($this->environment->ocspNonceMode, [], 300, 600),
            urlOverrides: $this->environment->ocspUrlOverrides,
            defaultUrl: $this->environment->ocspDefaultUrl,
            certIdHashOid: $this->environment->certIdHashOid(),
        );
    }

    public function signingService(): SigningService
    {
        if ($this->signingService === null) {
            $this->signingService = new SigningService(
                $this->clock,
                new LtExtender($this->tspClient(), $this->ocspClient(), $this->chainBuilder(), $this->trustStore()),
                logger: $this->logger,
            );
        }

        return $this->signingService;
    }

    public function validator(): ContainerValidator
    {
        if ($this->validator === null) {
            $this->validator = new ContainerValidator(
                new SignatureValidator($this->trustStore(), $this->policy),
                $this->clock,
                $this->policy,
            );
        }

        return $this->validator;
    }

    public function reader(): AsicReader
    {
        return new AsicReader();
    }

    public function writer(): AsicWriter
    {
        return new AsicWriter();
    }
}
