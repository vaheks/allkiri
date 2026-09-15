<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Trust;

use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Trust\InMemoryTrustStore;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustAnchor;
use Allkiri\Trust\TrustedList\TrustedList;
use Allkiri\Trust\TrustedList\TrustedListLoader;
use Allkiri\Trust\TrustedList\TrustedListParser;
use Allkiri\Trust\TrustedList\TrustedListStatus;
use Allkiri\Trust\TrustedListTrustStore;
use Allkiri\Trust\WithoutExpiredListsTrustStore;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * Anchors remember the trusted list they came from, so a signature resting on
 * one past its next update can be reported, and refused when a policy says so.
 */
#[CoversNothing]
final class ExpiredTrustedListTest extends TestCase
{
    private static function listStatus(string $label, ?string $nextUpdate): TrustedListStatus
    {
        return new TrustedListStatus($label, $nextUpdate === null ? null : new \DateTimeImmutable($nextUpdate));
    }

    public function testEveryAnchorOfTheEstonianTestListKnowsItsList(): void
    {
        $list = (new TrustedListParser())->parse((string) file_get_contents(__DIR__ . '/../../fixtures/captured/test-tl-EE_T.xml'), 'EE_T');

        self::assertNotSame([], $list->anchors());
        foreach ($list->anchors() as $anchor) {
            self::assertSame('EE_T', $anchor->trustedList?->label, $anchor->serviceName);
            self::assertSame('2030-01-01T00:00:00+00:00', $anchor->trustedList->nextUpdate?->format(DATE_ATOM), $anchor->serviceName);
            self::assertNull($anchor->trustedList->listOfLists, 'a list loaded on its own was reached through no list of lists');
        }

        $status = $list->anchors()[0]->trustedList;
        self::assertNotNull($status);
        self::assertNull($status->expiredAt(new \DateTimeImmutable('2030-01-01T00:00:00Z')), 'due at its next update is not yet overdue');
        self::assertSame($status, $status->expiredAt(new \DateTimeImmutable('2030-01-01T00:00:01Z')));
        self::assertNull($status->expiredAt(new \DateTimeImmutable('2030-01-03T00:00:00Z'), 2 * 86400), 'within the grace period');
        self::assertSame($status, $status->expiredAt(new \DateTimeImmutable('2030-01-03T00:00:01Z'), 2 * 86400));
    }

    public function testAListThatNamesNoNextUpdateCountsAsExpired(): void
    {
        $list = new TrustedList('EE', 'operator', 1, null, null, [], []);
        self::assertTrue($list->isExpiredAt(new \DateTimeImmutable('2000-01-01T00:00:00Z')));

        $status = self::listStatus('EE', null);
        self::assertSame($status, $status->expiredAt(new \DateTimeImmutable('2000-01-01T00:00:00Z'), 10 * 365 * 86400));
    }

    public function testAnExpiredListOfListsExpiresTheListsReachedThroughIt(): void
    {
        $listOfLists = self::listStatus('EU list of trusted lists', '2027-08-21T00:00:00Z');
        $national = self::listStatus('EE_T', '2030-01-01T00:00:00Z')->withListOfLists($listOfLists);

        self::assertNull($national->expiredAt(new \DateTimeImmutable('2027-08-20T00:00:00Z')));
        self::assertSame($listOfLists, $national->expiredAt(new \DateTimeImmutable('2027-09-01T00:00:00Z')));
        self::assertSame('EE_T', $national->expiredAt(new \DateTimeImmutable('2030-02-01T00:00:00Z'))?->label, 'the list itself is named before the list of lists');
    }

    public function testRefusingExpiredListsKeepsEveryOtherAnchor(): void
    {
        $at = new \DateTimeImmutable('2026-03-05T00:00:00Z');
        $expired = self::listStatus('old list', '2026-02-01T00:00:00Z');
        $current = self::listStatus('new list', '2026-06-01T00:00:00Z');
        $ca = TestPki::ca()->certificate;
        $tsa = TestPki::tsa()->certificate;

        $refusedCa = TrustAnchor::manual($ca, ServiceType::CaQc, 'refused')->withTrustedList($expired);
        $refusedTsa = TrustAnchor::manual($tsa, ServiceType::TsaQtst)->withTrustedList($expired);
        $currentCa = TrustAnchor::manual($ca, ServiceType::CaQc, 'current')->withTrustedList($current);
        $manual = TrustAnchor::manual(TestPki::ocspResponder()->certificate, ServiceType::OcspQc);
        $inner = new InMemoryTrustStore([$refusedCa, $refusedTsa, $currentCa, $manual]);

        $store = new WithoutExpiredListsTrustStore($inner, $at, 0);

        self::assertSame([$currentCa, $manual], $store->anchors(), 'an anchor added by hand has no list and never expires');
        self::assertSame([], $store->anchors([ServiceType::TsaQtst]));
        self::assertSame($currentCa, $store->findAnchor($ca), 'a current anchor for the certificate is found past a refused one');
        self::assertNull($store->findAnchor($tsa));
        self::assertSame([$currentCa], $store->findIssuerAnchors(TestPki::signerEc256()->certificate));
        self::assertSame($inner->anchors(), (new WithoutExpiredListsTrustStore($inner, $at, 40 * 86400))->anchors(), 'within the grace period nothing is refused');
    }

    public function testAListBuiltInCodeStampsItsAnchors(): void
    {
        $anchor = TrustAnchor::manual(TestPki::ca()->certificate, ServiceType::CaQc);
        $list = new TrustedList('EE', 'operator', 1, null, new \DateTimeImmutable('2026-02-01T00:00:00Z'), [$anchor], []);

        $store = TrustedListTrustStore::fromLists([$list], new TrustedListLoader(new MockHttpClient()));

        $status = $store->anchors()[0]->trustedList;
        self::assertNotNull($status);
        self::assertSame('EE', $status->label);
        self::assertSame('2026-02-01T00:00:00+00:00', $status->nextUpdate?->format(DATE_ATOM));
    }
}
