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
use Allkiri\MobileId\MobileIdAuthenticator;
use Allkiri\MobileId\MobileIdClient;
use Allkiri\MobileId\MobileIdConfiguration;
use Allkiri\MobileId\MobileIdSigner;
use Allkiri\Signing\SigningService;
use Allkiri\SmartId\SmartIdAuthenticator;
use Allkiri\SmartId\SmartIdClient;
use Allkiri\SmartId\SmartIdConfiguration;
use Allkiri\SmartId\SmartIdSigner;
use Allkiri\Trust\ChainBuilder;
use Allkiri\Trust\CompositeTrustStore;
use Allkiri\Trust\InMemoryTrustStore;
use Allkiri\Trust\ListOfListsTrustStore;
use Allkiri\Trust\TrustedList\TrustedListLoader;
use Allkiri\Trust\TrustedListTrustStore;
use Allkiri\Trust\TrustStore;
use Allkiri\Validation\ContainerValidator;
use Allkiri\Validation\SignatureValidator;
use Allkiri\Validation\ValidationPolicy;
use Allkiri\WebEid\WebEidAuthenticator;
use Allkiri\WebEid\WebEidConfiguration;
use Allkiri\WebEid\WebEidSigner;
use Allkiri\Xades\LtaExtender;
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

    private ?HttpClient $defaultHttp = null;

    public function __construct(
        private readonly Environment $environment,
        private readonly ?HttpClient $http = null,
        private readonly ClockInterface $clock = new SystemClock(),
        private readonly ?CacheInterface $cache = null,
        private readonly ValidationPolicy $policy = new ValidationPolicy(),
        private readonly NonceGenerator $nonces = new RandomNonceGenerator(),
        private readonly ?LoggerInterface $logger = null,
        /**
         * How containers are read, which is where the limit on how far a
         * container may expand lives. The default refuses the same archives
         * digidoc4j refuses; pass your own to change the thresholds.
         */
        private readonly AsicReader $reader = new AsicReader(),
        /**
         * How long after `prepare()` a signature can still be finalized. Raise
         * it if a Mobile-ID or Smart-ID session timeout is longer.
         */
        private readonly int $preparedSignatureTtlSeconds = SigningService::DEFAULT_PREPARED_SIGNATURE_TTL_SECONDS,
    ) {}

    public function environment(): Environment
    {
        return $this->environment;
    }

    /**
     * The client given to the constructor, or else the built-in one, built
     * once.
     */
    public function httpClient(): HttpClient
    {
        return $this->http ?? ($this->defaultHttp ??= $this->curlClient($this->environment->httpTimeoutSeconds));
    }

    /**
     * The built-in client, for when none was given. Mobile-ID and Smart-ID get
     * one of their own, so that a long poll can have the timeout it needs.
     */
    private function curlClient(int $timeoutSeconds): CurlHttpClient
    {
        return new CurlHttpClient($timeoutSeconds);
    }

    /**
     * Trust anchors from the configured trusted lists plus any extra ones.
     */
    public function trustStore(): TrustStore
    {
        if ($this->trustStore === null) {
            $stores = [];
            $loader = new TrustedListLoader($this->httpClient(), $this->cache ?? new ArrayCache(), clock: $this->clock, logger: $this->logger);
            if ($this->environment->listOfLists !== null) {
                $stores[] = new ListOfListsTrustStore($loader, $this->environment->listOfLists, logger: $this->logger);
            }
            if ($this->environment->trustedListSources !== []) {
                $stores[] = new TrustedListTrustStore($loader, $this->environment->trustedListSources);
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
        return new ChainBuilder($this->trustStore(), $this->policy->algorithmConstraints());
    }

    public function tspClient(): TspClient
    {
        return new TspClient($this->httpClient(), $this->environment->tsaUrl, nonces: $this->nonces, hashAlgorithm: $this->environment->timestampDigestAlgorithm, algorithmConstraints: $this->policy->algorithmConstraints());
    }

    public function ocspClient(): OcspClient
    {
        return new OcspClient(
            $this->httpClient(),
            $this->clock,
            nonces: $this->nonces,
            options: OcspVerificationOptions::forSigning($this->environment->ocspNonceMode)->withAlgorithmConstraints($this->policy->algorithmConstraints()),
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
                new LtaExtender($this->tspClient(), logger: $this->logger),
                logger: $this->logger,
                preparedSignatureTtlSeconds: $this->preparedSignatureTtlSeconds,
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
                $this->reader,
            );
        }

        return $this->validator;
    }

    /**
     * The Mobile-ID REST client.
     *
     * The relying-party identifier and name come with an SK contract, so the
     * configuration is passed in rather than derived from the environment;
     * `MobileIdConfiguration::demo()` needs neither.
     */
    public function mobileIdClient(MobileIdConfiguration $configuration): MobileIdClient
    {
        // Status requests are long polls: the service holds them open for the
        // poll timeout, so the HTTP client must be willing to wait longer than
        // that. Only the shared client is reused; the default one is rebuilt
        // with a timeout that fits.
        $http = $this->http ?? $this->curlClient(max($this->environment->httpTimeoutSeconds, $configuration->httpTimeoutSeconds()));

        return new MobileIdClient($configuration, $http, $this->logger);
    }

    public function mobileIdAuthenticator(MobileIdConfiguration $configuration): MobileIdAuthenticator
    {
        return new MobileIdAuthenticator(
            $this->mobileIdClient($configuration),
            $this->chainBuilder(),
            nonceGenerator: $this->nonces,
            clock: $this->clock,
        );
    }

    public function mobileIdSigner(MobileIdConfiguration $configuration): MobileIdSigner
    {
        return new MobileIdSigner($this->mobileIdClient($configuration), $this->signingService());
    }

    /**
     * The Smart-ID RP API v3 client.
     *
     * As with Mobile-ID, the relying-party identifier and name come with an SK
     * contract; `SmartIdConfiguration::demo()` needs neither.
     */
    public function smartIdClient(SmartIdConfiguration $configuration): SmartIdClient
    {
        $http = $this->http ?? $this->curlClient(max($this->environment->httpTimeoutSeconds, $configuration->httpTimeoutSeconds()));

        return new SmartIdClient($configuration, $http, $this->logger);
    }

    public function smartIdAuthenticator(SmartIdConfiguration $configuration): SmartIdAuthenticator
    {
        return new SmartIdAuthenticator(
            $this->smartIdClient($configuration),
            $this->chainBuilder(),
            $this->ocspClient(),
            nonceGenerator: $this->nonces,
            clock: $this->clock,
        );
    }

    public function smartIdSigner(SmartIdConfiguration $configuration): SmartIdSigner
    {
        return new SmartIdSigner($this->smartIdClient($configuration), $this->signingService());
    }

    /**
     * Signing in with an ID card.
     *
     * Nothing is negotiated with a service here, so the configuration carries
     * only the site's own origin, which is what the card signs.
     */
    public function webEidAuthenticator(WebEidConfiguration $configuration): WebEidAuthenticator
    {
        return new WebEidAuthenticator(
            $configuration,
            $this->trustStore(),
            $this->ocspClient(),
            $this->chainBuilder(),
            $this->nonces,
            $this->clock,
            $this->logger,
        );
    }

    public function webEidSigner(): WebEidSigner
    {
        return new WebEidSigner($this->signingService());
    }

    public function reader(): AsicReader
    {
        return $this->reader;
    }

    public function writer(): AsicWriter
    {
        return new AsicWriter();
    }
}
