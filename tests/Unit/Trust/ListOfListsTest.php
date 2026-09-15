<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Trust;

use Allkiri\Config\ArrayCache;
use Allkiri\Config\Environment;
use Allkiri\Crypto\Certificate;
use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Tests\Support\Clock\FrozenClock;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Trust\ListOfListsTrustStore;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustedList\ListOfListsSource;
use Allkiri\Trust\TrustedList\TrustedList;
use Allkiri\Trust\TrustedList\TrustedListException;
use Allkiri\Trust\TrustedList\TrustedListLoader;
use Allkiri\Trust\TrustedList\TrustedListPointer;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class ListOfListsTest extends TestCase
{
    private static function certificate(): Certificate
    {
        return TestPki::ca()->certificate;
    }

    /**
     * @param list<TrustedListPointer> $pointers
     */
    private static function listOfLists(array $pointers): TrustedList
    {
        return new TrustedList('EU', 'European Commission', 1, null, null, [], $pointers);
    }

    // --- choosing a pointer -------------------------------------------------

    /**
     * A territory publishes the same list twice: once as XML for a program and
     * once as a PDF for a person. In the real European list the Estonian PDF
     * comes first, so taking the first match fetches a document.
     */
    public function testTheMachineReadablePointerIsPreferredEvenWhenItIsSecond(): void
    {
        $list = self::listOfLists([
            new TrustedListPointer('EE', 'https://sr.riik.ee/tsl/estonian-tsl.pdf', [self::certificate()], TrustedListPointer::MIME_PDF),
            new TrustedListPointer('EE', 'https://sr.riik.ee/tsl/estonian-tsl.xml', [self::certificate()], TrustedListPointer::MIME_XML),
        ]);

        $pointer = $list->pointerTo('EE');

        self::assertNotNull($pointer);
        self::assertStringEndsWith('.xml', $pointer->location);
    }

    public function testAPointerWithNoMimeTypeIsStillUsable(): void
    {
        $list = self::listOfLists([
            new TrustedListPointer('LV', 'https://example.test/lv.xml', [self::certificate()]),
        ]);

        $pointer = $list->pointerTo('LV');

        self::assertNotNull($pointer);
        self::assertSame('https://example.test/lv.xml', $pointer->location);
    }

    /**
     * A territory that publishes only a PDF has no list a program can read, and
     * saying so beats handing back a document.
     */
    public function testATerritoryWithOnlyAPdfHasNoMachineReadableList(): void
    {
        $list = self::listOfLists([
            new TrustedListPointer('LT', 'https://example.test/lt.pdf', [self::certificate()], TrustedListPointer::MIME_PDF),
        ]);

        self::assertNull($list->pointerTo('LT'));
        self::assertCount(1, $list->pointersTo('LT'));
    }

    public function testAnyPointerCanBeAskedForExplicitly(): void
    {
        $list = self::listOfLists([
            new TrustedListPointer('EE', 'https://example.test/ee.pdf', [self::certificate()], TrustedListPointer::MIME_PDF),
            new TrustedListPointer('EE', 'https://example.test/ee.xml', [self::certificate()], TrustedListPointer::MIME_XML),
        ]);

        self::assertSame('https://example.test/ee.pdf', $list->pointerTo('EE', TrustedListPointer::MIME_PDF)?->location);
        self::assertSame('https://example.test/ee.pdf', $list->pointerTo('EE', null)?->location, 'no preference means the first');
        self::assertCount(2, $list->pointersTo('EE'));
    }

    public function testAnUnknownTerritoryHasNoPointer(): void
    {
        self::assertNull(self::listOfLists([])->pointerTo('EE'));
        self::assertSame([], self::listOfLists([])->pointersTo('EE'));
    }

    // --- the source ---------------------------------------------------------

    /**
     * Without pinned signers anything that answers the URL would be believed,
     * which is the one thing this arrangement must not allow.
     */
    public function testAListOfListsWithNoPinnedSignersIsRefused(): void
    {
        $this->expectExceptionMessageMatches('/needs the certificates that may sign it/');

        new ListOfListsSource(ListOfListsSource::EU_URL, [], ['EE']);
    }

    public function testATerritoryCodeMustLookLikeOne(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new ListOfListsSource(ListOfListsSource::EU_URL, [self::certificate()], ['Estonia']);
    }

    /**
     * A test list of lists names its territory "EE_T" rather than "EE".
     */
    public function testATestTerritoryCodeIsAccepted(): void
    {
        $source = new ListOfListsSource(ListOfListsSource::EU_URL, [self::certificate()], ['EE_T']);

        self::assertSame(['EE_T'], $source->territories);
    }

    public function testAtLeastOneTerritoryIsNeeded(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new ListOfListsSource(ListOfListsSource::EU_URL, [self::certificate()], []);
    }

    /**
     * A pointer naming no signing certificate cannot be followed: there would
     * be nothing to verify the list against.
     */
    public function testAPointerWithoutSigningCertificatesIsRefused(): void
    {
        $source = new ListOfListsSource(ListOfListsSource::EU_URL, [self::certificate()], ['EE']);

        try {
            $source->sourceFor(new TrustedListPointer('EE', 'https://example.test/ee.xml', []));
            self::fail('Expected a TrustedListException');
        } catch (TrustedListException $exception) {
            self::assertSame(TrustedListException::REASON_NO_PINS, $exception->reason);
        }
    }

    public function testAPointerBecomesASourceCarryingItsOwnSigners(): void
    {
        $source = new ListOfListsSource(ListOfListsSource::EU_URL, [self::certificate()], ['EE']);
        $signer = TestPki::tsa()->certificate;

        $ee = $source->sourceFor(new TrustedListPointer('EE', 'https://example.test/ee.xml', [$signer], TrustedListPointer::MIME_XML));

        self::assertSame('https://example.test/ee.xml', $ee->url);
        self::assertCount(1, $ee->allowedSigners);
        self::assertTrue($ee->allowedSigners[0]->equals($signer));
        self::assertSame('EE trusted list', $ee->name);
    }

    // --- the store ----------------------------------------------------------

    /**
     * A territory the list of lists does not carry must fail loudly rather than
     * quietly yielding an empty trust store, which would reject every
     * signature with a confusing reason.
     */
    public function testATerritoryTheListDoesNotCarryIsReported(): void
    {
        $http = new MockHttpClient();
        $http->respond('https://lotl.test/', 200, 'application/vnd.etsi.tsl+xml', (string) file_get_contents('tests/fixtures/captured/test-lotl-tl-mp-test-EE.xml'));

        $signer = Certificate::fromPem((string) file_get_contents('resources/trust/test/test-tsl-signer.pem'));
        $source = new ListOfListsSource('https://lotl.test/lotl.xml', [$signer], ['LV']);
        $store = new ListOfListsTrustStore($this->loader($http), $source);

        try {
            $store->load();
            self::fail('Expected a TrustedListException');
        } catch (TrustedListException $exception) {
            self::assertSame(TrustedListException::REASON_NO_SUCH_LIST, $exception->reason);
            self::assertStringContainsString('LV', $exception->getMessage());
        }
    }

    /**
     * The test list of lists and the list it points to, walked with the same
     * code production uses.
     */
    public function testTheChainIsWalkedFromTheListOfListsToTheNationalList(): void
    {
        $http = new MockHttpClient();
        $http->respond('https://lotl.test/', 200, 'application/vnd.etsi.tsl+xml', (string) file_get_contents('tests/fixtures/captured/test-lotl-tl-mp-test-EE.xml'));
        $http->respond('https://open-eid.github.io/test-TL/EE_T.xml', 200, 'application/vnd.etsi.tsl+xml', (string) file_get_contents('tests/fixtures/captured/test-tl-EE_T.xml'));

        $signer = Certificate::fromPem((string) file_get_contents('resources/trust/test/test-tsl-signer.pem'));
        // The test list of lists uses the test territory code, not "EE".
        $source = new ListOfListsSource('https://lotl.test/lotl.xml', [$signer], ['EE_T']);
        $store = new ListOfListsTrustStore($this->loader($http), $source);

        $store->load();

        self::assertNotSame([], $store->anchors([ServiceType::CaQc]));
        $names = implode(' | ', array_map(static fn($a): string => $a->certificate->subjectDn(), $store->anchors()));
        self::assertStringContainsString('ESTEID2018', $names);
    }

    /**
     * A national list is only as current as the list of lists that named its
     * signers, so its anchors carry both.
     */
    public function testNationalAnchorsKnowTheListOfListsTheyWereReachedThrough(): void
    {
        $http = new MockHttpClient();
        $http->respond('https://lotl.test/', 200, 'application/vnd.etsi.tsl+xml', (string) file_get_contents('tests/fixtures/captured/test-lotl-tl-mp-test-EE.xml'));
        $http->respond('https://open-eid.github.io/test-TL/EE_T.xml', 200, 'application/vnd.etsi.tsl+xml', (string) file_get_contents('tests/fixtures/captured/test-tl-EE_T.xml'));
        $signer = Certificate::fromPem((string) file_get_contents('resources/trust/test/test-tsl-signer.pem'));
        $store = new ListOfListsTrustStore($this->loader($http), new ListOfListsSource('https://lotl.test/lotl.xml', [$signer], ['EE_T']));

        $store->load();
        $anchors = $store->anchors();

        self::assertNotSame([], $anchors);
        foreach ($anchors as $anchor) {
            self::assertStringContainsString('EE_T', (string) $anchor->trustedList?->label);
            self::assertSame('EU list of trusted lists', $anchor->trustedList?->listOfLists?->label);
        }
        $status = $anchors[0]->trustedList;
        self::assertNotNull($status);
        self::assertNull($status->expiredAt(new \DateTimeImmutable('2027-08-20T00:00:00Z')));
        self::assertSame('EU list of trusted lists', $status->expiredAt(new \DateTimeImmutable('2027-09-01T00:00:00Z'))?->label, 'the list of lists runs out first');
    }

    // --- the environment ----------------------------------------------------

    public function testTheProductionEnvironmentShipsTheJournalCertificates(): void
    {
        $source = Environment::production()->listOfLists;

        self::assertNotNull($source);
        self::assertSame(ListOfListsSource::EU_URL, $source->url);
        self::assertCount(6, $source->allowedSigners, 'the Official Journal publishes six');
        self::assertSame(['EE'], $source->territories);
    }

    /**
     * Every wither must carry the list of lists along, or asking for a
     * different timestamp service would silently drop production trust.
     */
    public function testTheListOfListsSurvivesEveryWither(): void
    {
        $environment = Environment::production()
            ->withTsaUrl('http://tsa.example.test')
            ->withHttpTimeout(60)
            ->withSivaUrl(null)
            ->withOcspDefaultUrl('http://ocsp.example.test');

        self::assertNotNull($environment->listOfLists);
        self::assertCount(6, $environment->listOfLists->allowedSigners);
    }

    public function testTheListOfListsCanBeReplacedOrRemoved(): void
    {
        $custom = new ListOfListsSource('https://example.test/lotl.xml', [self::certificate()], ['LV', 'LT']);

        self::assertSame($custom, Environment::production()->withListOfLists($custom)->listOfLists);
        self::assertNull(Environment::production()->withListOfLists(null)->listOfLists);
    }

    public function testTheDemoEnvironmentUsesAPinnedListRatherThanTheChain(): void
    {
        // The test trusted list is not reachable through the European list of
        // lists, so demo pins it directly.
        self::assertNull(Environment::demo()->listOfLists);
        self::assertNotSame([], Environment::demo()->trustedListSources);
    }

    private function loader(MockHttpClient $http): TrustedListLoader
    {
        return new TrustedListLoader($http, new ArrayCache(), clock: new FrozenClock('2026-09-01T00:00:00Z'));
    }
}
