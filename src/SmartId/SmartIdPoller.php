<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Clock\Sleeper;
use Allkiri\Clock\SystemSleeper;

/**
 * Waits for a person to finish with the Smart-ID app.
 *
 * Only for applications that can block, such as a console tool or a queue
 * worker. A web application should call {@see SmartIdClient::sessionStatus()}
 * once per browser poll instead and keep its request threads free.
 */
final class SmartIdPoller
{
    public function __construct(
        private readonly SmartIdClient $client,
        private readonly Sleeper $sleeper = new SystemSleeper(),
    ) {}

    /**
     * Poll until the session finishes or the configured session timeout passes.
     *
     * Returns the status whatever it says, including a refusal; callers decide
     * whether to throw. {@see waitForSuccess()} throws instead.
     */
    public function wait(SmartIdSession $session): SmartIdSessionStatus
    {
        $configuration = $this->client->configuration();
        $budgetMs = $configuration->sessionTimeoutSeconds * 1000;
        $spentMs = 0;

        while (true) {
            $remainingMs = $budgetMs - $spentMs;
            if ($remainingMs <= 0) {
                return new SmartIdSessionStatus(SmartIdSessionStatus::STATE_COMPLETE, SmartIdEndResult::Timeout);
            }
            // Never ask for longer than the service accepts, nor longer than
            // the caller's own budget: the last poll must not overrun it.
            $timeoutMs = max(1_000, min($configuration->pollTimeoutMs, $remainingMs));

            $startedAt = microtime(true);
            $status = $this->client->sessionStatus($session->sessionId, $timeoutMs);
            $elapsedMs = (int) round((microtime(true) - $startedAt) * 1000);

            if ($status->isComplete()) {
                return $status;
            }

            // Charge the budget at least the timeout we asked for, so a service
            // that answers instantly still terminates in a bounded number of
            // rounds instead of spinning.
            $spentMs += max($timeoutMs, $elapsedMs);

            if ($elapsedMs < 1_000) {
                $this->sleeper->sleep(1.0);
            }
        }
    }

    /**
     * @throws SmartIdSessionException when the person did not complete the session
     */
    public function waitForSuccess(SmartIdSession $session): SmartIdSessionStatus
    {
        return $this->wait($session)->requireOk();
    }
}
