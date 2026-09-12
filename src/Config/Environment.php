<?php

declare(strict_types=1);

namespace Allkiri\Config;

use Allkiri\Crypto\Asn1\Oids;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\Ocsp\NonceMode;
use Allkiri\Resources;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustAnchor;
use Allkiri\Trust\TrustedList\ListOfListsSource;
use Allkiri\Trust\TrustedList\TrustedListSource;

/**
 * Which services to talk to and which trust anchors to believe.
 *
 * {@see demo()} is ready to use: the endpoints are free and the anchors are
 * SK's and Zetes' published test PKIs. {@see production()} needs the trusted
 * list's signing certificates pinned before it will load anything, because
 * that pin is the whole trust decision.
 */
final readonly class Environment
{
    /**
     * @param array<string, string>   $ocspUrlOverrides issuer subject DN => responder URL, for contract endpoints and certificates without AIA
     * @param list<TrustedListSource> $trustedListSources
     * @param list<TrustAnchor>       $extraTrustAnchors  anchors a trusted list does not carry
     */
    public function __construct(
        public string $name,
        public string $tsaUrl,
        public ?string $ocspDefaultUrl,
        public array $ocspUrlOverrides = [],
        public NonceMode $ocspNonceMode = NonceMode::Required,
        public array $trustedListSources = [],
        public array $extraTrustAnchors = [],
        public int $httpTimeoutSeconds = 30,
        public HashAlgorithm $timestampDigestAlgorithm = HashAlgorithm::SHA256,
        public ?string $sivaUrl = null,
        public ?ListOfListsSource $listOfLists = null,
    ) {}

    /**
     * The free test environments: SK's demo timestamp and OCSP services, RIA's
     * test trusted list, and the Zetes test CAs for Thales cards, which the
     * test trusted list does not list.
     */
    public static function demo(): self
    {
        return new self(
            name: 'demo',
            tsaUrl: 'http://tsa.demo.sk.ee/tsa',
            ocspDefaultUrl: 'http://demo.sk.ee/ocsp',
            trustedListSources: [
                new TrustedListSource(
                    'https://open-eid.github.io/test-TL/EE_T.xml',
                    [self::certificate('test/test-tsl-signer.pem')],
                    null,
                    'Estonian test trusted list',
                ),
            ],
            extraTrustAnchors: [
                TrustAnchor::manual(self::certificate('test/zetes/testEEGovCA2025.pem'), ServiceType::CaQc, 'Test EEGovCA2025', 'zetes test PKI'),
                TrustAnchor::manual(self::certificate('test/zetes/testESTEID2025.pem'), ServiceType::CaQc, 'Test ESTEID2025', 'zetes test PKI'),
            ],
            sivaUrl: 'https://siva-demo.eesti.ee/V3/validate',
        );
    }

    /**
     * The live services. Timestamping and the commercial OCSP endpoint need a
     * contract with SK; the free AIA responders named in each certificate do
     * not, which is why no default OCSP URL is set here.
     *
     * Trust comes from the European list of trusted lists, verified against the
     * certificates the Official Journal publishes, which is the only trust
     * material shipped. `withTrustedListSources()` replaces that with lists you
     * pin yourself.
     */
    public static function production(): self
    {
        return new self(
            name: 'production',
            tsaUrl: 'http://tsa.sk.ee',
            ocspDefaultUrl: null,
            ocspUrlOverrides: [],
            trustedListSources: [],
            sivaUrl: 'https://siva.eesti.ee/V3/validate',
            listOfLists: self::euListOfLists(),
        );
    }

    /**
     * The European list of trusted lists, with the certificates the Official
     * Journal publishes as the only thing shipped.
     *
     * Read `resources/trust/eu/README.md` before relying on it: those
     * certificates decide what your application will treat as qualified, and
     * they should be checked against the Journal rather than against this
     * library.
     *
     * @param list<string> $territories two-letter codes whose lists to follow
     */
    public static function euListOfLists(array $territories = ['EE']): ListOfListsSource
    {
        $signers = [];
        for ($i = 1; $i <= 6; ++$i) {
            $signers[] = self::certificate(\sprintf('eu/lotl-signer-%d.pem', $i));
        }

        return new ListOfListsSource(ListOfListsSource::EU_URL, $signers, $territories);
    }

    /**
     * Null takes trust back to whatever `withTrustedListSources()` supplies.
     */
    public function withListOfLists(?ListOfListsSource $source): self
    {
        return $this->but(listOfLists: $source, listOfListsGiven: true);
    }

    /**
     * @param list<TrustedListSource> $sources
     */
    public function withTrustedListSources(array $sources): self
    {
        return $this->but(trustedListSources: $sources);
    }

    /**
     * @param list<TrustAnchor> $anchors
     */
    public function withExtraTrustAnchors(array $anchors): self
    {
        return $this->but(extraTrustAnchors: $anchors);
    }

    public function withTsaUrl(string $url): self
    {
        return $this->but(tsaUrl: $url);
    }

    /**
     * Null means: use the responder each certificate names in its AIA extension.
     */
    public function withOcspDefaultUrl(?string $url): self
    {
        return $this->but(ocspDefaultUrl: $url, ocspDefaultUrlGiven: true);
    }

    /**
     * @param array<string, string> $overrides
     */
    public function withOcspUrlOverrides(array $overrides): self
    {
        return $this->but(ocspUrlOverrides: $overrides);
    }

    public function withOcspNonceMode(NonceMode $mode): self
    {
        return $this->but(ocspNonceMode: $mode);
    }

    public function withHttpTimeout(int $seconds): self
    {
        return $this->but(httpTimeoutSeconds: $seconds);
    }

    /**
     * Null disables the SiVa second opinion.
     */
    public function withSivaUrl(?string $url): self
    {
        return $this->but(sivaUrl: $url, sivaUrlGiven: true);
    }

    /**
     * Copy with some fields replaced.
     *
     * The nullable fields need a companion flag, because null is a meaningful
     * value for them and "not given" has to be told apart from "set to null".
     *
     * @param array<string, string>|null   $ocspUrlOverrides
     * @param list<TrustedListSource>|null $trustedListSources
     * @param list<TrustAnchor>|null       $extraTrustAnchors
     */
    private function but(
        ?string $tsaUrl = null,
        ?string $ocspDefaultUrl = null,
        bool $ocspDefaultUrlGiven = false,
        ?array $ocspUrlOverrides = null,
        ?NonceMode $ocspNonceMode = null,
        ?array $trustedListSources = null,
        ?array $extraTrustAnchors = null,
        ?int $httpTimeoutSeconds = null,
        ?string $sivaUrl = null,
        bool $sivaUrlGiven = false,
        ?ListOfListsSource $listOfLists = null,
        bool $listOfListsGiven = false,
    ): self {
        return new self(
            $this->name,
            $tsaUrl ?? $this->tsaUrl,
            $ocspDefaultUrlGiven ? $ocspDefaultUrl : $this->ocspDefaultUrl,
            $ocspUrlOverrides ?? $this->ocspUrlOverrides,
            $ocspNonceMode ?? $this->ocspNonceMode,
            $trustedListSources ?? $this->trustedListSources,
            $extraTrustAnchors ?? $this->extraTrustAnchors,
            $httpTimeoutSeconds ?? $this->httpTimeoutSeconds,
            $this->timestampDigestAlgorithm,
            $sivaUrlGiven ? $sivaUrl : $this->sivaUrl,
            $listOfListsGiven ? $listOfLists : $this->listOfLists,
        );
    }

    /**
     * SHA-1 is what responders in the wild expect in a CertID.
     */
    public function certIdHashOid(): string
    {
        return Oids::SHA1;
    }

    private static function certificate(string $relativePath): Certificate
    {
        return Certificate::fromPem(Resources::read('trust/' . $relativePath));
    }
}
