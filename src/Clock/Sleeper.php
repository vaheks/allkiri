<?php

declare(strict_types=1);

namespace Allkiri\Clock;

/**
 * Waiting, made injectable so tests never actually wait.
 */
interface Sleeper
{
    public function sleep(float $seconds): void;
}
