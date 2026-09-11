<?php

declare(strict_types=1);

namespace Allkiri\Clock;

use Psr\Clock\ClockInterface;

/**
 * The real clock. Always answers in UTC because every timestamp allkiri
 * writes or compares (SigningTime, OCSP producedAt, TSA genTime) is UTC.
 */
final class SystemClock implements ClockInterface
{
    public function now(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
    }
}
