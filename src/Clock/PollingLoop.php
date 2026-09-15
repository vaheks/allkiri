<?php

declare(strict_types=1);

namespace Allkiri\Clock;

/**
 * The long-polling loop Mobile-ID and Smart-ID sessions are waited for with.
 *
 * The service holds each request open for the poll timeout, so this is not a
 * busy loop. The short sleep only guards against a service that answers at
 * once, which would otherwise turn it into one.
 *
 * @internal
 */
final class PollingLoop
{
    private function __construct() {}

    /**
     * Ask until there is an answer or the session budget is spent.
     *
     * @template T of object
     *
     * @param int               $sessionTimeoutSeconds how long to keep asking in all
     * @param int               $pollTimeoutMs         the longest the service may hold one request
     * @param \Closure(int): ?T $ask                   one request the service may hold for that many milliseconds; the answer once the session has finished, null while it runs
     *
     * @return T|null null when the budget ran out first
     */
    public static function until(Sleeper $sleeper, int $sessionTimeoutSeconds, int $pollTimeoutMs, \Closure $ask): ?object
    {
        $budgetMs = $sessionTimeoutSeconds * 1000;
        $spentMs = 0;

        while (true) {
            $remainingMs = $budgetMs - $spentMs;
            if ($remainingMs <= 0) {
                return null;
            }
            // Never ask for longer than the service accepts, nor longer than
            // the caller's own budget: the last poll must not overrun it.
            $timeoutMs = max(1_000, min($pollTimeoutMs, $remainingMs));

            $startedAt = microtime(true);
            $answer = $ask($timeoutMs);
            $elapsedMs = (int) round((microtime(true) - $startedAt) * 1000);

            if ($answer !== null) {
                return $answer;
            }

            // Charge the budget at least the timeout asked for, so a mocked or
            // instantaneous service still terminates in a bounded number of
            // rounds instead of spinning.
            $spentMs += max($timeoutMs, $elapsedMs);

            if ($elapsedMs < 1_000) {
                $sleeper->sleep(1.0);
            }
        }
    }
}
