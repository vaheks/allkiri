<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Trust;

use Allkiri\Config\ArrayCache;
use Allkiri\Config\Environment;
use Allkiri\Crypto\KeyPair;
use Allkiri\Resources;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Tests\Support\RecordingLogger;
use Allkiri\Tests\Support\Trust\TestTrustedLists;
use Allkiri\Trust\ListOfListsTrustStore;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustedList\ListOfListsSource;
use Allkiri\Trust\TrustedList\TrustedListException;
use Allkiri\Trust\TrustedList\TrustedListLoader;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Following the pivot lists by which the Commission changes the certificates
 * that sign the list of lists, as its pivot explanation describes: starting
 * from the set an Official Journal publication gives, each pivot newer than
 * that publication, oldest first, verified against the set the one before
 * gave.
 *
 * The keys: A is the shipped certificate, B and C are ones only pivots
 * introduce.
 */
#[CoversClass(ListOfListsTrustStore::class)]
final class PivotListTest extends TestCase
{
    private const LOTL = 'https://lotl.allkiri.test/eu-lotl.xml';

    private const JOURNAL = 'https://journal.allkiri.test/C/2026/1944';

    private const PIVOT_1 = 'https://lotl.allkiri.test/eu-lotl-pivot-1.xml';

    private const PIVOT_2 = 'https://lotl.allkiri.test/eu-lotl-pivot-2.xml';

    private const ESTONIA = 'https://ee.allkiri.test/tsl.xml';

    private MockHttpClient $http;

    private RecordingLogger $logger;

    protected function setUp(): void
    {
        $this->http = new MockHttpClient();
        $this->logger = new RecordingLogger();
        $this->http->respond(self::ESTONIA, 200, 'application/xml', TestTrustedLists::nationalList(TestPki::signerRsaPerson(), 'EE', TestPki::ca()->certificate));
    }

    private static function a(): KeyPair
    {
        return TestPki::signerRsa();
    }

    private static function b(): KeyPair
    {
        return TestPki::signerEc256();
    }

    private static function c(): KeyPair
    {
        return TestPki::signerEc384();
    }

    /**
     * @param list<KeyPair> $names
     * @param list<string>  $uris
     */
    private function publish(string $url, KeyPair $signedBy, array $names, array $uris, string $location = self::LOTL): void
    {
        $this->http->respond($url, 200, 'application/xml', TestTrustedLists::listOfLists(
            $signedBy,
            array_map(static fn(KeyPair $key) => $key->certificate, $names),
            $uris,
            $location,
            [['territory' => 'EE', 'location' => self::ESTONIA, 'signers' => [TestPki::signerRsaPerson()->certificate]]],
        ));
    }

    private function store(?string $journal = self::JOURNAL): ListOfListsTrustStore
    {
        $source = new ListOfListsSource(self::LOTL, [self::a()->certificate], ['EE'], officialJournalUrl: $journal);

        return new ListOfListsTrustStore(new TrustedListLoader($this->http, new ArrayCache()), $source, [ServiceType::CaQc], $this->logger);
    }

    private function assertLoads(ListOfListsTrustStore $store): void
    {
        self::assertCount(1, $store->anchors(), 'the Estonian authority is reached');
    }

    public function testWithNoNewerPivotTheShippedCertificatesDecide(): void
    {
        $this->publish(self::LOTL, self::a(), [self::a()], [self::JOURNAL, self::PIVOT_1]);

        $this->assertLoads($this->store());

        self::assertSame(0, $this->http->requestCount(self::PIVOT_1), 'a pivot older than the shipped publication is not fetched');
        self::assertSame(1, $this->http->requestCount(self::LOTL), 'the list is downloaded once, though it is read before it is trusted');
    }

    public function testACertificateAPivotIntroducedIsTrusted(): void
    {
        $this->publish(self::PIVOT_1, self::a(), [self::a(), self::b()], [self::PIVOT_1, self::JOURNAL]);
        $this->publish(self::LOTL, self::b(), [self::a(), self::b()], [self::PIVOT_1, self::JOURNAL]);

        $this->assertLoads($this->store());

        self::assertStringContainsString('Followed the pivot list ' . self::PIVOT_1 . ': 2 certificates', $this->logger->transcript());
    }

    /**
     * The same list, without the publication to start from: nothing is
     * followed, and the new certificate is refused, as it was before pivots
     * were followed.
     */
    public function testWithoutAPublicationNoPivotIsFollowed(): void
    {
        $this->publish(self::PIVOT_1, self::a(), [self::a(), self::b()], [self::PIVOT_1, self::JOURNAL]);
        $this->publish(self::LOTL, self::b(), [self::a(), self::b()], [self::PIVOT_1, self::JOURNAL]);

        try {
            $this->store(null)->anchors();
            self::fail('A list of lists signed by an unshipped certificate was accepted');
        } catch (TrustedListException $exception) {
            self::assertSame(TrustedListException::REASON_SIGNER_NOT_ALLOWED, $exception->reason);
        }
        self::assertSame(0, $this->http->requestCount(self::PIVOT_1));
    }

    /**
     * B signs the second pivot, and only the first introduced B. Taking them
     * newest first would check the second against A alone and end at the wrong
     * set.
     */
    public function testAChainOfPivotsIsFollowedOldestFirst(): void
    {
        $this->publish(self::PIVOT_1, self::a(), [self::a(), self::b()], [self::PIVOT_1, self::JOURNAL]);
        $this->publish(self::PIVOT_2, self::b(), [self::b(), self::c()], [self::PIVOT_2, self::PIVOT_1, self::JOURNAL]);
        $this->publish(self::LOTL, self::c(), [self::b(), self::c()], [self::PIVOT_2, self::PIVOT_1, self::JOURNAL]);

        $this->assertLoads($this->store());
    }

    /**
     * Anyone can put a list at a URL the list of lists names, or change what
     * the list of lists names before it is trusted. A pivot counts only when a
     * certificate trusted so far signed it.
     */
    public function testAPivotSignedByAnUntrustedKeyAddsNothing(): void
    {
        $this->publish(self::PIVOT_1, self::c(), [self::c()], [self::PIVOT_1, self::JOURNAL]);
        $this->publish(self::LOTL, self::c(), [self::c()], [self::PIVOT_1, self::JOURNAL]);

        try {
            $this->store()->anchors();
            self::fail('A pivot signed by an untrusted key widened trust');
        } catch (TrustedListException $exception) {
            self::assertSame(TrustedListException::REASON_SIGNER_NOT_ALLOWED, $exception->reason);
        }
        self::assertStringContainsString('Skipped the pivot list ' . self::PIVOT_1, $this->logger->transcript());
    }

    public function testAPivotThatCannotBeFetchedIsSkipped(): void
    {
        $this->http->respond(self::PIVOT_1, 404, 'text/html', 'gone');
        $this->publish(self::LOTL, self::a(), [self::a()], [self::PIVOT_1, self::JOURNAL]);

        $this->assertLoads($this->store());

        self::assertStringContainsString('Skipped the pivot list ' . self::PIVOT_1 . ': Trusted list ' . self::PIVOT_1 . ' answered HTTP 404', $this->logger->transcript());
    }

    /**
     * The addresses are read out of a list that nothing has verified yet, so
     * they are followed only where a pivot list of that list can be: over
     * https, on the same host. Anywhere else and this server would be making a
     * request chosen by a document it does not trust.
     *
     * @param string $where an address the unverified list might name
     */
    #[DataProvider('addressesThatAreNotPivots')]
    public function testAPivotAddressAwayFromTheListIsNotFetched(string $where, string $why): void
    {
        $this->publish(self::LOTL, self::a(), [self::a()], [$where, self::JOURNAL]);

        $this->assertLoads($this->store());

        self::assertSame(0, $this->http->requestCount($where), $why);
        self::assertStringContainsString('which is not an https address on lotl.allkiri.test', $this->logger->transcript());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function addressesThatAreNotPivots(): iterable
    {
        yield 'another host' => ['https://elsewhere.allkiri.test/eu-lotl-pivot-1.xml', 'a host the list of lists does not live on is not asked'];
        yield 'the private network' => ['http://127.0.0.1:80/eu-lotl-pivot-1.xml', 'an address on this machine is not asked'];
        yield 'a metadata service' => ['http://169.254.169.254/latest/meta-data/eu-lotl-pivot.xml', 'a link-local address is not asked'];
        yield 'plain http on the right host' => ['http://lotl.allkiri.test/eu-lotl-pivot-1.xml', 'the right host over plain http is not asked'];
    }

    /**
     * Each pivot is fetched on the word of a list nothing has verified yet, so
     * a document naming more of them than could exist is an attempt to make
     * this server fetch, not a long history.
     */
    public function testAListNamingImplausiblyManyPivotsIsFollowedNowhere(): void
    {
        $many = [];
        for ($i = 1; $i <= ListOfListsSource::MAX_PIVOTS + 1; ++$i) {
            $many[] = \sprintf('https://lotl.allkiri.test/eu-lotl-pivot-%d.xml', $i);
        }
        $this->publish(self::LOTL, self::a(), [self::a()], [...$many, self::JOURNAL]);

        $this->assertLoads($this->store());

        self::assertSame(0, $this->http->requestCount($many[0]), 'no pivot is fetched');
        self::assertStringContainsString('more than the ' . ListOfListsSource::MAX_PIVOTS . ' that could plausibly exist', $this->logger->transcript());
    }

    /**
     * After a new publication and the end of its transition period, the
     * Commission drops the old publication and the pivots before it. Every
     * pivot still named is then tried, and a release is due.
     */
    public function testWhenThePublicationIsNoLongerNamedEveryPivotIsTried(): void
    {
        $newJournal = 'https://journal.allkiri.test/C/2027/1';
        $this->publish(self::PIVOT_2, self::a(), [self::a(), self::b()], [self::PIVOT_2, $newJournal]);
        $this->publish(self::LOTL, self::b(), [self::a(), self::b()], [self::PIVOT_2, $newJournal]);

        $this->assertLoads($this->store());

        self::assertStringContainsString('no longer names ' . self::JOURNAL . ', the Official Journal publication the shipped certificates come from; a release with the new publication is due', $this->logger->transcript());
    }

    /**
     * During a transition, the new publication is listed above the pivots
     * that led to it. It is not a pivot, and those pivots still are.
     */
    public function testDuringATransitionTheNewPublicationIsPassedOver(): void
    {
        $newJournal = 'https://journal.allkiri.test/C/2027/1';
        $this->publish(self::PIVOT_1, self::a(), [self::a(), self::b()], [self::PIVOT_1, self::JOURNAL]);
        $this->publish(self::LOTL, self::b(), [self::a(), self::b()], [$newJournal, self::PIVOT_1, self::JOURNAL]);

        $this->assertLoads($this->store());

        self::assertSame(0, $this->http->requestCount('https://journal.allkiri.test/'));
    }

    public function testANewAddressInTheNewestPivotIsOnlyReported(): void
    {
        $this->publish(self::PIVOT_1, self::a(), [self::a(), self::b()], [self::PIVOT_1, self::JOURNAL], 'https://moved.allkiri.test/eu-lotl.xml');
        $this->publish(self::LOTL, self::b(), [self::a(), self::b()], [self::PIVOT_1, self::JOURNAL]);

        $this->assertLoads($this->store());

        self::assertSame(0, $this->http->requestCount('https://moved.allkiri.test/'));
        self::assertStringContainsString('The newest pivot list places the list of trusted lists at https://moved.allkiri.test/eu-lotl.xml, but it is read from ' . self::LOTL, $this->logger->transcript());
    }

    /**
     * The publication production starts from is the one the shipped
     * certificates come from, which that directory's README names.
     */
    public function testProductionStartsFromThePublicationTheShippedCertificatesComeFrom(): void
    {
        self::assertSame(Environment::EU_OFFICIAL_JOURNAL_URL, Environment::euListOfLists()->officialJournalUrl);
        self::assertStringContainsString('| URL | <' . Environment::EU_OFFICIAL_JOURNAL_URL . '> |', Resources::read('trust/eu/README.md'));
    }
}
