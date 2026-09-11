<?php

declare(strict_types=1);

namespace Allkiri\Tests\Integration;

use Allkiri\Clock\SystemClock;
use Allkiri\Config\Environment;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustedList\TrustedListLoader;

/**
 * RIA's test trusted list, fetched live.
 *
 * This is the check that catches a trusted list that has been re-signed with a
 * new certificate, which would otherwise only surface when signing breaks.
 */
final class TrustedListLiveTest extends IntegrationTestCase
{
    public function testTheLiveTestTrustedListStillVerifiesAgainstTheBundledPin(): void
    {
        $environment = Environment::demo();
        $source = $environment->trustedListSources[0];
        $loader = new TrustedListLoader(self::http(30), clock: new SystemClock());

        $list = $loader->load($source);

        self::assertSame('EE_T', $list->territory);
        self::assertGreaterThanOrEqual(34, $list->sequenceNumber, 'the list only moves forward');
        self::assertNotSame([], $list->anchors(ServiceType::caTypes()));
        self::assertNotSame([], $list->anchors(ServiceType::tsaTypes()));
        self::assertNotSame([], $list->anchors(ServiceType::ocspTypes()));

        $names = array_map(static fn($anchor): string => $anchor->serviceName, $list->anchors(ServiceType::caTypes()));
        self::assertStringContainsString('TEST of ESTEID2018', implode(' | ', $names));

        if ($list->isExpiredAt(new \DateTimeImmutable())) {
            self::markTestIncomplete(\sprintf('The test trusted list expired on %s; RIA has not refreshed it', $list->nextUpdate?->format(DATE_ATOM) ?? 'an unknown date'));
        }
        self::assertNotNull($list->nextUpdate);
    }
}
