<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit;

use Allkiri\Allkiri;
use Allkiri\Config\ArrayCache;
use Allkiri\Config\Environment;
use Allkiri\Container\AsicContainer;
use Allkiri\Container\DataFile;
use Allkiri\Crypto\Ocsp\NonceMode;
use Allkiri\Signing\LocalKeySigner;
use Allkiri\Signing\SignatureLevel;
use Allkiri\Tests\Support\Clock\FrozenClock;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Tests\Support\Pki\MockOcspResponder;
use Allkiri\Tests\Support\Pki\MockTsa;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustAnchor;
use Allkiri\Trust\TrustedList\ListOfListsSource;
use Allkiri\Trust\TrustedList\TrustedListException;
use Allkiri\Trust\TrustedList\TrustedListSource;
use Allkiri\Validation\FindingCodes;
use Allkiri\Validation\Report\Indication;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Allkiri::class)]
#[CoversClass(Environment::class)]
#[CoversClass(ArrayCache::class)]
final class AllkiriTest extends TestCase
{
    public function testVersionAndUserAgent(): void
    {
        self::assertMatchesRegularExpression('/^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/', Allkiri::VERSION);
        self::assertStringStartsWith('allkiri/' . Allkiri::VERSION, Allkiri::USER_AGENT);
    }

    public function testTheDemoEnvironmentPointsAtTheFreeTestServices(): void
    {
        $environment = Environment::demo();

        self::assertSame('demo', $environment->name);
        self::assertSame('http://tsa.demo.sk.ee/tsa', $environment->tsaUrl);
        self::assertSame('http://demo.sk.ee/ocsp', $environment->ocspDefaultUrl);
        self::assertSame('https://siva-demo.eesti.ee/V3/validate', $environment->sivaUrl);
        self::assertSame(NonceMode::Required, $environment->ocspNonceMode);

        // The Estonian test trusted list, pinned to its published signer.
        self::assertCount(1, $environment->trustedListSources);
        $source = $environment->trustedListSources[0];
        self::assertSame('https://open-eid.github.io/test-TL/EE_T.xml', $source->url);
        self::assertCount(1, $source->allowedSigners);
        self::assertSame('Test TSL', $source->allowedSigners[0]->commonName());

        // The Zetes test CAs for Thales cards, which that list does not carry.
        $names = array_map(static fn(TrustAnchor $a): ?string => $a->certificate->commonName(), $environment->extraTrustAnchors);
        self::assertSame(['Test EEGovCA2025', 'Test ESTEID2025'], $names);
        foreach ($environment->extraTrustAnchors as $anchor) {
            self::assertSame(ServiceType::CaQc, $anchor->serviceType);
            self::assertTrue($anchor->isTrustworthyAt(new \DateTimeImmutable('2026-09-11T00:00:00Z')));
        }
    }

    public function testTheProductionEnvironmentTakesTrustFromTheEuropeanChain(): void
    {
        $environment = Environment::production();

        self::assertSame('production', $environment->name);
        self::assertSame('http://tsa.sk.ee', $environment->tsaUrl);
        self::assertNull($environment->ocspDefaultUrl, 'the free AIA responder named in each certificate is used instead');
        self::assertSame('https://siva.eesti.ee/V3/validate', $environment->sivaUrl);
        self::assertSame([], $environment->extraTrustAnchors);

        // No list is pinned by hand. Trust is reached through the European list
        // of trusted lists, which is verified against the certificates the
        // Official Journal publishes and which allkiri ships.
        self::assertSame([], $environment->trustedListSources);
        self::assertNotNull($environment->listOfLists);
        self::assertCount(6, $environment->listOfLists->allowedSigners);
    }

    /**
     * Production trust needs the network, and a failure to reach it must be
     * reported rather than quietly yielding an empty trust store that would
     * reject every signature for the wrong reason.
     */
    public function testProductionTrustFailsLoudlyWhenTheListCannotBeFetched(): void
    {
        $allkiri = new Allkiri(Environment::production(), new MockHttpClient());

        $this->expectException(TrustedListException::class);

        $allkiri->trustStore()->anchors();
    }

    /**
     * Validation needs the same trust, but reports its absence on each
     * signature instead of throwing, so the caller still has a report to show.
     */
    public function testValidationReportsProductionTrustThatCannotBeFetched(): void
    {
        $allkiri = new Allkiri(Environment::production(), new MockHttpClient());

        $report = $allkiri->validator()->validateFile(__DIR__ . '/../fixtures/containers/valid-asice-esteid2018.asice');

        $signature = $report->signatures[0];
        self::assertSame(Indication::Indeterminate, $signature->indication);
        self::assertTrue($signature->has(FindingCodes::TRUST_ANCHORS_UNAVAILABLE));
        self::assertStringContainsString(ListOfListsSource::EU_URL, implode("\n", array_map(static fn($f): string => $f->message, $signature->errors())));
    }

    public function testTheEnvironmentIsImmutableAndConfigurable(): void
    {
        $demo = Environment::demo();
        $changed = $demo
            ->withTsaUrl('http://tsa.example.test/tsa')
            ->withOcspDefaultUrl('http://ocsp.example.test/')
            ->withOcspUrlOverrides(['C=EE, CN=Some CA' => 'http://ocsp.example.test/some-ca'])
            ->withOcspNonceMode(NonceMode::IfPresent)
            ->withHttpTimeout(5)
            ->withSivaUrl(null)
            ->withTrustedListSources([])
            ->withExtraTrustAnchors([]);

        self::assertSame('http://tsa.demo.sk.ee/tsa', $demo->tsaUrl, 'the original is untouched');
        self::assertSame('http://tsa.example.test/tsa', $changed->tsaUrl);
        self::assertSame('http://ocsp.example.test/', $changed->ocspDefaultUrl);
        self::assertSame(['C=EE, CN=Some CA' => 'http://ocsp.example.test/some-ca'], $changed->ocspUrlOverrides);
        self::assertSame(NonceMode::IfPresent, $changed->ocspNonceMode);
        self::assertSame(5, $changed->httpTimeoutSeconds);
        self::assertSame([], $changed->trustedListSources);
        self::assertSame('demo', $changed->name);

        // Null is a meaningful value for both nullable fields, so setting them
        // to null must clear them rather than be mistaken for "leave it alone".
        self::assertNull($changed->sivaUrl);
        self::assertNull($demo->withOcspDefaultUrl(null)->ocspDefaultUrl);
        self::assertSame('http://demo.sk.ee/ocsp', $demo->withHttpTimeout(9)->ocspDefaultUrl, 'other withers leave them alone');
        self::assertSame('https://siva-demo.eesti.ee/V3/validate', $demo->withHttpTimeout(9)->sivaUrl);
    }

    public function testTheFactoryWiresAWorkingSignAndValidateRoundTrip(): void
    {
        // A local environment pointing at the in-process mock services.
        $clock = new FrozenClock('2026-04-01T09:00:00Z');
        $http = new MockHttpClient();
        MockTsa::register($http, $clock);
        MockOcspResponder::register($http, $clock);
        $environment = new \Allkiri\Config\Environment(
            name: 'test',
            tsaUrl: MockTsa::URL,
            ocspDefaultUrl: MockOcspResponder::URL,
            extraTrustAnchors: [
                TrustAnchor::manual(TestPki::ca()->certificate, ServiceType::CaQc, 'test CA'),
                TrustAnchor::manual(TestPki::tsa()->certificate, ServiceType::TsaQtst, 'test TSA'),
                TrustAnchor::manual(TestPki::ocspResponder()->certificate, ServiceType::OcspQc, 'test responder'),
            ],
        );
        $allkiri = new Allkiri($environment, $http, $clock);

        $result = $allkiri->signingService()->signWith(
            AsicContainer::create(DataFile::fromString('leping.txt', 'Tere!')),
            LocalKeySigner::fromKeyPair(TestPki::signerEc256()),
        );
        self::assertSame(SignatureLevel::LT, $result->level);

        $report = $allkiri->validator()->validate($allkiri->writer()->write($result->container), 'leping.asice');
        self::assertTrue($report->isValid(), implode('; ', array_map(static fn($f): string => $f->message, $report->signatures[0]->errors())));
        self::assertSame('2026-04-01T09:00:00+00:00', $report->validationTime->format(DATE_ATOM));

        // The same objects come back, so the trusted list is fetched once.
        self::assertSame($allkiri->signingService(), $allkiri->signingService());
        self::assertSame($allkiri->validator(), $allkiri->validator());
        self::assertSame($allkiri->trustStore(), $allkiri->trustStore());
    }

    public function testTheFactoryLoadsAnchorsFromATrustedList(): void
    {
        $tlXml = (string) file_get_contents(__DIR__ . '/../fixtures/captured/test-tl-EE_T.xml');
        $signer = \Allkiri\Crypto\Certificate::fromPem((string) file_get_contents(__DIR__ . '/../fixtures/certs/Test_TSL_signer.pem'));
        $url = 'https://open-eid.github.io/test-TL/EE_T.xml';
        $http = (new MockHttpClient())->respond($url, 200, 'application/xml', $tlXml);

        $environment = Environment::demo()
            ->withTrustedListSources([new TrustedListSource($url, [$signer], null, 'EE test list')])
            ->withExtraTrustAnchors(Environment::demo()->extraTrustAnchors);
        $allkiri = new Allkiri($environment, $http, new FrozenClock('2026-09-11T00:00:00Z'));

        $anchors = $allkiri->trustStore()->anchors();
        $names = array_map(static fn(TrustAnchor $a): ?string => $a->certificate->commonName(), $anchors);

        self::assertContains('TEST of ESTEID2018', $names, 'from the trusted list');
        self::assertContains('Test ESTEID2025', $names, 'from the bundled Zetes anchors');
        self::assertSame(1, $http->requestCount($url));
        $allkiri->trustStore()->anchors();
        self::assertSame(1, $http->requestCount($url), 'the list is fetched once per process');
    }

    public function testTheProcessCacheHonoursTimeToLive(): void
    {
        $cache = new ArrayCache();

        self::assertFalse($cache->has('k'));
        self::assertSame('fallback', $cache->get('k', 'fallback'));
        $cache->set('k', 'v');
        self::assertTrue($cache->has('k'));
        self::assertSame('v', $cache->get('k'));

        $cache->set('expired', 'v', -1);
        self::assertNull($cache->get('expired'));
        self::assertFalse($cache->has('expired'));

        $cache->setMultiple(['a' => 1, 'b' => 2]);
        self::assertSame(['a' => 1, 'b' => 2], iterator_to_array((function () use ($cache): \Generator {
            foreach ($cache->getMultiple(['a', 'b']) as $key => $value) {
                yield $key => $value;
            }
        })()));
        $cache->deleteMultiple(['a', 'b']);
        self::assertFalse($cache->has('a'));

        $cache->set('x', 'v', new \DateInterval('PT1H'));
        self::assertSame('v', $cache->get('x'));
        $cache->delete('x');
        self::assertFalse($cache->has('x'));
        $cache->set('y', 'v');
        $cache->clear();
        self::assertFalse($cache->has('y'));
    }
}
