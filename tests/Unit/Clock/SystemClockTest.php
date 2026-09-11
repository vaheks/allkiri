<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Clock;

use Allkiri\Clock\SystemClock;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(SystemClock::class)]
final class SystemClockTest extends TestCase
{
    public function testNowIsUtcAndCurrent(): void
    {
        $before = time();
        $now = (new SystemClock())->now();

        self::assertSame('UTC', $now->getTimezone()->getName());
        self::assertGreaterThanOrEqual($before, $now->getTimestamp());
        self::assertLessThanOrEqual(time() + 1, $now->getTimestamp());
    }
}
