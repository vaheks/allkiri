<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Trust;

use Allkiri\Crypto\Certificate;
use Allkiri\Tests\Support\Cache\ArrayCache;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Trust\ChainBuilder;
use Allkiri\Trust\ServiceStatus;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustAnchor;
use Allkiri\Trust\TrustedList\TrustedListException;
use Allkiri\Trust\TrustedList\TrustedListLoader;
use Allkiri\Trust\TrustedList\TrustedListParser;
use Allkiri\Trust\TrustedList\TrustedListSource;
use Allkiri\Trust\TrustedList\TrustedListVerifier;
use Allkiri\Trust\TrustedListTrustStore;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class TrustedListTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/../../fixtures/';

    private const TL_URL = 'https://open-eid.github.io/test-TL/EE_T.xml';

    private const LOTL_URL = 'https://open-eid.github.io/test-TL/tl-mp-test-EE.xml';

    private static function tlXml(): string
    {
        return (string) file_get_contents(self::FIXTURES . 'captured/test-tl-EE_T.xml');
    }

    private static function signer(): Certificate
    {
        return Certificate::fromPem((string) file_get_contents(self::FIXTURES . 'certs/Test_TSL_signer.pem'));
    }

    public function testTheEstonianTestListParsesIntoTheExpectedAnchors(): void
    {
        $list = (new TrustedListParser())->parse(self::tlXml(), 'EE_T');

        self::assertSame('EE_T', $list->territory, 'the test list uses its own territory code');
        self::assertSame('Information System Authority', $list->schemeOperatorName, 'RIA operates the scheme; SK only provides the services');
        self::assertSame(34, $list->sequenceNumber);
        self::assertSame('2026-07-21', $list->issueDate?->format('Y-m-d'));
        self::assertNotNull($list->nextUpdate);
        self::assertFalse($list->isExpiredAt(new \DateTimeImmutable('2026-09-11T00:00:00Z')));
        self::assertTrue($list->isExpiredAt($list->nextUpdate->modify('+1 second')));

        // Service names carry a descriptive suffix after the CA name.
        $cas = implode(' | ', self::names($list->anchors(ServiceType::caTypes())));
        self::assertStringContainsString('TEST of ESTEID2018', $cas);
        self::assertStringContainsString('TEST of ESTEID-SK 2015', $cas);
        self::assertStringContainsString('TEST of EID-SK 2016', $cas);
        self::assertStringContainsString('TEST of KLASS3-SK 2016', $cas);

        $tsas = $list->anchors(ServiceType::tsaTypes());
        self::assertNotSame([], $tsas);
        self::assertStringContainsString('TSA', implode(' | ', self::names($tsas)));

        $ocsps = $list->anchors(ServiceType::ocspTypes());
        self::assertNotSame([], $ocsps);
        self::assertStringContainsString('OCSP RESPONDER', implode(' | ', self::names($ocsps)));

        foreach ($list->anchors() as $anchor) {
            self::assertNotSame([], $anchor->statusHistory, $anchor->serviceName);
            self::assertSame('EE_T', $anchor->source);
        }
        // A national list points back up at the list of lists it belongs to.
        self::assertCount(1, $list->pointers);
        self::assertSame(self::LOTL_URL, $list->pointers[0]->location);
    }

    public function testTheTestListOfListsCarriesThePointerToTheEstonianList(): void
    {
        $lotl = (new TrustedListParser())->parse((string) file_get_contents(self::FIXTURES . 'captured/test-lotl-tl-mp-test-EE.xml'));

        self::assertCount(1, $lotl->pointers);
        $pointer = $lotl->pointers[0];
        self::assertSame(self::TL_URL, $pointer->location);
        self::assertSame('EE_T', $pointer->territory);
        self::assertCount(1, $pointer->signingCertificates);
        self::assertTrue($pointer->allows(self::signer()), 'the pointer names the certificate that signs EE_T.xml');
        self::assertNotNull($lotl->pointerTo('EE_T'));
        self::assertNull($lotl->pointerTo('LV'));
        // Where a list of lists names its Official Journal publication and pivots.
        self::assertSame(['https://open-eid.github.io/test-TL/'], $lotl->schemeInformationUris);
    }

    public function testTheAnchorsAreUsableForRealChainBuilding(): void
    {
        $list = (new TrustedListParser())->parse(self::tlXml());
        $store = new \Allkiri\Trust\InMemoryTrustStore($list->anchors());
        $leaf = Certificate::fromPem((string) file_get_contents(self::FIXTURES . 'certs/TEST_ESTEID2018_signer_JOEORG.pem'));

        $chain = (new ChainBuilder($store))->build($leaf, [], new \DateTimeImmutable('2024-09-02T12:36:44Z'), ServiceType::caTypes());

        self::assertSame(2, $chain->length(), 'the list anchors the issuing CA directly');
        self::assertStringStartsWith('TEST of ESTEID2018', $chain->anchor->serviceName);
        self::assertSame(ServiceStatus::Granted, $chain->anchor->statusAt(new \DateTimeImmutable('2024-09-02T12:36:44Z')));
    }

    public function testSignatureVerificationAcceptsOnlyThePinnedSigner(): void
    {
        $verifier = new TrustedListVerifier();
        $xml = self::tlXml();

        self::assertTrue($verifier->verify($xml, [self::signer()])->equals(self::signer()));

        $otherCertificate = Certificate::fromPem((string) file_get_contents(self::FIXTURES . 'certs/TEST_of_ESTEID2018.pem'));
        try {
            $verifier->verify($xml, [$otherCertificate]);
            self::fail('a list signed by an unpinned certificate was accepted');
        } catch (TrustedListException $e) {
            self::assertSame(TrustedListException::REASON_SIGNER_NOT_ALLOWED, $e->reason);
        }

        try {
            $verifier->verify($xml, []);
            self::fail('a list was accepted with no pins configured');
        } catch (TrustedListException $e) {
            self::assertSame(TrustedListException::REASON_NO_PINS, $e->reason);
        }
    }

    public function testTamperedListIsRejected(): void
    {
        // Change one byte of a service name: the signature no longer covers the document.
        $tampered = str_replace('TEST of ESTEID2018', 'TEST of ESTEID2019', self::tlXml(), $count);
        self::assertGreaterThan(0, $count);

        try {
            (new TrustedListVerifier())->verify($tampered, [self::signer()]);
            self::fail('a tampered trusted list was accepted');
        } catch (TrustedListException $e) {
            self::assertSame(TrustedListException::REASON_SIGNATURE, $e->reason);
        }
    }

    public function testLoaderFetchesVerifiesCachesAndReverifies(): void
    {
        $cache = new ArrayCache();
        $http = (new MockHttpClient())->respond(self::TL_URL, 200, 'application/xml', self::tlXml());
        $loader = new TrustedListLoader($http, $cache);
        $source = new TrustedListSource(self::TL_URL, [self::signer()], ServiceType::caTypes(), 'EE test list');

        $first = $loader->load($source);
        $second = $loader->load($source);

        self::assertSame($first->sequenceNumber, $second->sequenceNumber);
        self::assertSame(1, $http->requestCount(), 'the second load comes from the cache');

        // A poisoned cache must not slip anchors past the signature check.
        $cache->set($source->cacheKey(), str_replace('TEST of ESTEID2018', 'EVIL CA', self::tlXml()));
        try {
            $loader->load($source);
            self::fail('a tampered cache entry was trusted');
        } catch (TrustedListException $e) {
            self::assertSame(TrustedListException::REASON_SIGNATURE, $e->reason);
        }
    }

    /**
     * Writing a cache hit back would renew the entry every time, and under
     * steady use a list past its next update would never be fetched again.
     */
    public function testTheLoaderWritesToTheCacheOnlyWhenItFetched(): void
    {
        $cache = new ArrayCache();
        $http = (new MockHttpClient())->respond(self::TL_URL, 200, 'application/xml', self::tlXml());
        $loader = new TrustedListLoader($http, $cache);
        $source = new TrustedListSource(self::TL_URL, [self::signer()]);

        $loader->load($source);
        self::assertSame(1, $cache->writes, 'a fetched list is stored');

        $loader->load($source);
        $loader->load($source);
        self::assertSame(1, $http->requestCount());
        self::assertSame(1, $cache->writes, 'a list read from the cache is not stored again');
    }

    public function testLoaderReportsTransportFailures(): void
    {
        $http = (new MockHttpClient())->respond(self::TL_URL, 503, 'text/plain', 'maintenance');
        $source = new TrustedListSource(self::TL_URL, [self::signer()]);

        try {
            (new TrustedListLoader($http))->load($source);
            self::fail('HTTP 503 accepted');
        } catch (TrustedListException $e) {
            self::assertSame(TrustedListException::REASON_TRANSPORT, $e->reason);
        }

        try {
            (new TrustedListLoader(new MockHttpClient()))->load($source);
            self::fail('unreachable host accepted');
        } catch (TrustedListException $e) {
            self::assertSame(TrustedListException::REASON_TRANSPORT, $e->reason);
        }
    }

    public function testTrustStoreLoadsLazilyAndOnlyTheRequestedServiceTypes(): void
    {
        $http = (new MockHttpClient())
            ->respond(self::TL_URL, 200, 'application/xml', self::tlXml())
            ->respond(self::LOTL_URL, 200, 'application/xml', (string) file_get_contents(self::FIXTURES . 'captured/test-lotl-tl-mp-test-EE.xml'));
        $loader = new TrustedListLoader($http, new ArrayCache());
        $store = new TrustedListTrustStore($loader, [new TrustedListSource(self::TL_URL, [self::signer()], ServiceType::caTypes(), 'EE test list')]);

        self::assertSame(0, $http->requestCount(), 'nothing is fetched before the anchors are needed');
        $anchors = $store->anchors();
        self::assertNotSame([], $anchors);
        self::assertSame(1, $http->requestCount());
        self::assertSame([], $store->anchors(ServiceType::tsaTypes()), 'the source restricted itself to CA services');

        $leaf = Certificate::fromPem((string) file_get_contents(self::FIXTURES . 'certs/TEST_ESTEID2018_signer_JOEORG.pem'));
        self::assertNotSame([], $store->findIssuerAnchors($leaf));
        self::assertNull($store->findAnchor($leaf));
        self::assertNotNull($store->findAnchor(Certificate::fromPem((string) file_get_contents(self::FIXTURES . 'certs/TEST_of_ESTEID2018.pem'))));
    }

    /**
     * @param list<TrustAnchor> $anchors
     *
     * @return list<string>
     */
    private static function names(array $anchors): array
    {
        $names = [];
        foreach ($anchors as $anchor) {
            $names[] = $anchor->serviceName;
        }

        return array_values(array_unique($names));
    }

    public function testMalformedInputIsReportedNotCrashed(): void
    {
        try {
            (new TrustedListParser())->parse('<html><body>not a trusted list</body></html>');
            self::fail('HTML accepted as a trusted list');
        } catch (TrustedListException $e) {
            self::assertSame(TrustedListException::REASON_MALFORMED, $e->reason);
        }

        $this->expectException(TrustedListException::class);
        (new TrustedListParser())->parse('<not xml');
    }
}
