<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Clock;

use Psr\Clock\ClockInterface;

/**
 * A clock that only moves when a test tells it to.
 */
final class FrozenClock implements ClockInterface
{
    private \DateTimeImmutable $now;

    public function __construct(string|\DateTimeImmutable $now = '2026-01-15T12:00:00Z')
    {
        $this->now = \is_string($now) ? new \DateTimeImmutable($now, new \DateTimeZone('UTC')) : $now->setTimezone(new \DateTimeZone('UTC'));
    }

    public function now(): \DateTimeImmutable
    {
        return $this->now;
    }

    public function set(string|\DateTimeImmutable $now): void
    {
        $this->now = \is_string($now) ? new \DateTimeImmutable($now, new \DateTimeZone('UTC')) : $now->setTimezone(new \DateTimeZone('UTC'));
    }

    /**
     * @param string $interval a DateInterval spec such as "PT15M" or "P1D"
     */
    public function advance(string $interval): void
    {
        $this->now = $this->now->add(new \DateInterval($interval));
    }
}
