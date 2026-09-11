<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

use Allkiri\Clock\Sleeper;
use Allkiri\Clock\SystemSleeper;

/**
 * Waits for a person to finish with their phone.
 *
 * Only for applications that can block, such as a console tool or a queue
 * worker. A web application should call {@see MobileIdClient::status()} once
 * per browser poll instead and keep its request threads free.
 */
final class MobileIdPoller
{
    public function __construct(
        private readonly MobileIdClient $client,
        private readonly Sleeper $sleeper = new SystemSleeper(),
    ) {}

    /**
     * Poll until the session finishes or the configured session timeout passes.
     *
     * The service holds each request open for the poll timeout, so this is not
     * a busy loop. The short sleep only guards against a service that answers
     * immediately, which would otherwise turn this into one.
     *
     * @throws MobileIdSessionException when the person did not complete the session
     * @throws MobileIdApiException
     */
    public function wait(MobileIdSession $session): MobileIdSessionStatus
    {
        $configuration = $this->client->configuration();
        $budgetMs = $configuration->sessionTimeoutSeconds * 1000;
        $spentMs = 0;

        while (true) {
            $remainingMs = $budgetMs - $spentMs;
            if ($remainingMs <= 0) {
                throw new MobileIdSessionException(MobileIdResult::Timeout);
            }
            // Never ask for longer than the service accepts, nor longer than
            // the caller's own budget: the last poll must not overrun it.
            $timeoutMs = max(1_000, min($configuration->pollTimeoutMs, $remainingMs));

            $startedAt = microtime(true);
            $status = $this->client->status($session->type, $session->sessionId, $timeoutMs);
            $elapsedMs = (int) round((microtime(true) - $startedAt) * 1000);

            if ($status->isComplete()) {
                if (!$status->isOk()) {
                    throw new MobileIdSessionException($status->result ?? MobileIdResult::Timeout);
                }

                return $status;
            }

            // Charge the budget at least the timeout we asked for, so a mocked
            // or instantaneous service still terminates in a bounded number of
            // rounds instead of spinning.
            $spentMs += max($timeoutMs, $elapsedMs);

            if ($elapsedMs < 1_000) {
                $this->sleeper->sleep(1.0);
            }
        }
    }
}
