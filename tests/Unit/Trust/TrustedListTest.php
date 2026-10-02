<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Trust;

use Allkiri\Crypto\Certificate;
use Allkiri\Tests\Support\Cache\ArrayCache;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Tests\Support\Trust\TestTrustedLists;
use Allkiri\Trust\ChainBuilder;
use Allkiri\Trust\ListOfListsTrustStore;
use Allkiri\Trust\ServiceStatus;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustAnchor;
use Allkiri\Trust\TrustedList\ListOfListsSource;
use Allkiri\Trust\TrustedList\TrustedListException;
use Allkiri\Trust\TrustedList\TrustedListLoader;
use Allkiri\Trust\TrustedList\TrustedListParser;
use Allkiri\Trust\TrustedList\TrustedListSource;
use Allkiri\Trust\TrustedList\TrustedListVerifier;
use Allkiri\Trust\TrustedListTrustStore;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
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

    /**
     * The test list of lists signs its root by Id (URI="#ID0001"). Nested
     * inside a forged list, its signature still verifies; what the parser
     * reads is the forged root, so the signature must be refused for not
     * covering it.
     *
     * @return iterable<string, array{string}>
     */
    public static function wrappedLists(): iterable
    {
        $genuine = (string) file_get_contents(self::FIXTURES . 'captured/test-lotl-tl-mp-test-EE.xml');
        $body = (string) preg_replace('/^<\?xml[^>]*\?>/', '', $genuine);
        // The genuine root's namespaces, so that inclusive canonicalisation
        // of a signature moved under the forged root comes out the same.
        $forged = static fn(string $inside): string => '<?xml version="1.0" encoding="UTF-8"?>'
            . '<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
            . ' xmlns:tslx="http://uri.etsi.org/02231/v2/additionaltypes#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">'
            . '<SchemeInformation><TSLSequenceNumber>999</TSLSequenceNumber><SchemeTerritory>EU</SchemeTerritory>'
            . '<PointersToOtherTSL><OtherTSLPointer><TSLLocation>https://evil.test/EE_T.xml</TSLLocation></OtherTSLPointer></PointersToOtherTSL>'
            . '</SchemeInformation>'
            . $inside
            . '</TrustServiceStatusList>';

        yield 'the whole signed list nested' => [$forged('<Hidden>' . $body . '</Hidden>')];

        // The signature moved up to the forged root, the signed list nested
        // without it: the enveloped transform then removes nothing from the
        // nested list, whose digest is unchanged.
        self::assertSame(1, preg_match('~<ds:Signature\b.*</ds:Signature>~s', $body, $match));
        $unsigned = str_replace($match[0], '', $body);
        yield 'the signature moved to the forged root' => [$forged($match[0] . '<Hidden>' . $unsigned . '</Hidden>')];
    }

    #[DataProvider('wrappedLists')]
    public function testASignedListNestedInAForgedOneIsRefused(string $wrapped): void
    {
        $signer = Certificate::fromPem((string) file_get_contents(__DIR__ . '/../../../resources/trust/test/test-tsl-signer.pem'));
        $genuine = (string) file_get_contents(self::FIXTURES . 'captured/test-lotl-tl-mp-test-EE.xml');
        self::assertTrue((new TrustedListVerifier())->verify($genuine, [$signer])->equals($signer), 'the list signed by Id verifies as it is');

        try {
            (new TrustedListVerifier())->verify($wrapped, [$signer]);
            self::fail('a forged list around a signed one was accepted');
        } catch (TrustedListException $e) {
            self::assertSame(TrustedListException::REASON_SIGNATURE, $e->reason);
        }
    }

    /**
     * The cache is not a source of trust: what it holds is verified again,
     * and a forged list placed there is refused like one from the network.
     */
    public function testAForgedListInTheCacheAddsNoAnchors(): void
    {
        $signer = Certificate::fromPem((string) file_get_contents(__DIR__ . '/../../../resources/trust/test/test-tsl-signer.pem'));
        $source = new ListOfListsSource('https://lotl.allkiri.test/lotl.xml', [$signer], ['EE_T']);
        $cache = new ArrayCache();
        foreach (self::wrappedLists() as [$wrapped]) {
            $cache->set($source->toSource()->cacheKey(), $wrapped);
            $store = new ListOfListsTrustStore(new TrustedListLoader(new MockHttpClient(), $cache), $source);
            try {
                $store->load();
                self::fail('a forged list from the cache was used');
            } catch (TrustedListException $e) {
                self::assertSame(TrustedListException::REASON_SIGNATURE, $e->reason);
            }
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
        self::assertSame(2, $cache->writes, 'a fetched list is stored, and its sequence number');

        $loader->load($source);
        $loader->load($source);
        self::assertSame(1, $http->requestCount());
        self::assertSame(2, $cache->writes, 'a list read from the cache is not stored again');
    }

    /**
     * An older list is genuinely signed, so its signature says nothing against
     * it, but it may grant a service withdrawn since. Served again from the
     * same address, after a newer one, it is refused.
     */
    public function testAListOlderThanOneAlreadyServedIsRefused(): void
    {
        $url = 'https://tl.allkiri.test/lotl.xml';
        $signer = TestPki::signerRsaPerson();
        $list = static fn(int $sequence): string => TestTrustedLists::listOfLists($signer, [$signer->certificate], [], $url, [], $sequence);
        $cache = new ArrayCache();
        $source = new TrustedListSource($url, [$signer->certificate], cacheTtlSeconds: 60);

        self::assertSame(5, (new TrustedListLoader((new MockHttpClient())->respond($url, 200, 'application/xml', $list(5)), $cache))->load($source)->sequenceNumber);
        // The list's own entry expires; the sequence number is remembered.
        $cache->delete($source->cacheKey());
        self::assertSame(6, (new TrustedListLoader((new MockHttpClient())->respond($url, 200, 'application/xml', $list(6)), $cache))->load($source)->sequenceNumber, 'a newer one is fine');
        $cache->delete($source->cacheKey());

        try {
            (new TrustedListLoader((new MockHttpClient())->respond($url, 200, 'application/xml', $list(5)), $cache))->load($source);
            self::fail('an older list was taken after a newer one');
        } catch (TrustedListException $e) {
            self::assertSame(TrustedListException::REASON_ROLLED_BACK, $e->reason);
            self::assertStringContainsString('is number 5, but number 6 has already been served', $e->getMessage());
        }
    }

    /**
     * A status says since when, and a past one counts only for the kind of
     * service it was. A current withdrawal without a time used to be dated at
     * the epoch, before every grant in the history, so the service read as
     * granted; a past status as a timestamping unit counted for a CA.
     */
    public function testAServiceStatusIsReadOnlyWithItsTimeAndItsType(): void
    {
        $withHistory = static function (bool $currentHasTime, string $pastType, bool $pastHasTime): string {
            $document = new \DOMDocument();
            $document->loadXML(TestTrustedLists::nationalList(TestPki::signerRsaPerson(), 'EE', TestPki::ca()->certificate));
            $xpath = new \DOMXPath($document);
            $xpath->registerNamespace('tsl', TrustedListParser::NS_TSL);
            $one = static function (string $query, ?\DOMNode $context = null) use ($xpath): \DOMElement {
                $found = $xpath->query($query, $context);
                $element = $found === false ? null : $found->item(0);
                self::assertInstanceOf(\DOMElement::class, $element, $query);

                return $element;
            };
            $info = $one('//tsl:ServiceInformation');
            $one('tsl:ServiceStatus', $info)->textContent = ServiceStatus::Withdrawn->value;
            $current = $one('tsl:StatusStartingTime', $info);
            if ($currentHasTime) {
                $current->textContent = '2025-01-01T00:00:00Z';
            } else {
                $info->removeChild($current);
            }
            $service = $info->parentNode;
            self::assertNotNull($service);
            $instance = $service->appendChild($document->createElementNS(TrustedListParser::NS_TSL, 'ServiceHistory'))
                ->appendChild($document->createElementNS(TrustedListParser::NS_TSL, 'ServiceHistoryInstance'));
            $instance->appendChild($document->createElementNS(TrustedListParser::NS_TSL, 'ServiceTypeIdentifier', $pastType));
            $instance->appendChild($document->createElementNS(TrustedListParser::NS_TSL, 'ServiceStatus', ServiceStatus::Granted->value));
            if ($pastHasTime) {
                $instance->appendChild($document->createElementNS(TrustedListParser::NS_TSL, 'StatusStartingTime', '2020-01-01T00:00:00Z'));
            }

            return (string) $document->saveXML();
        };
        $parse = static fn(string $xml): array => (new TrustedListParser())->parse($xml)->anchors;
        $in = static fn(string $at): \DateTimeImmutable => new \DateTimeImmutable($at);

        // As it should be: granted from 2020, withdrawn in 2025.
        $anchors = $parse($withHistory(true, ServiceType::CaQc->value, true));
        self::assertCount(1, $anchors);
        self::assertTrue($anchors[0]->isTrustworthyAt($in('2023-01-01T00:00:00Z')));
        self::assertFalse($anchors[0]->isTrustworthyAt($in('2026-01-01T00:00:00Z')));

        self::assertSame([], $parse($withHistory(false, ServiceType::CaQc->value, true)), 'a current status without a time is no anchor');

        $asTimestamping = $parse($withHistory(true, ServiceType::TsaQtst->value, true));
        self::assertFalse($asTimestamping[0]->isTrustworthyAt($in('2023-01-01T00:00:00Z')), 'a grant as another kind of service does not count');

        $undated = $parse($withHistory(true, ServiceType::CaQc->value, false));
        self::assertFalse($undated[0]->isTrustworthyAt($in('2023-01-01T00:00:00Z')), 'a past status without a time does not count');
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
