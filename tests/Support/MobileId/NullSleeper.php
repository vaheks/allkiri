<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\MobileId;

use Allkiri\Clock\Sleeper;

/**
 * Records how long it was asked to wait, and waits none of it.
 */
final class NullSleeper implements Sleeper
{
    /** @var list<float> */
    public array $slept = [];

    public function sleep(float $seconds): void
    {
        $this->slept[] = $seconds;
    }

    public function total(): float
    {
        return array_sum($this->slept);
    }
}
