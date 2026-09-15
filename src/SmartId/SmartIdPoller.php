<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Clock\PollingLoop;
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
     * Returns the status whatever it says, including a refusal, and a TIMEOUT
     * status when the timeout passes first; callers decide whether to throw.
     * {@see waitForSuccess()} throws instead.
     */
    public function wait(SmartIdSession $session): SmartIdSessionStatus
    {
        $configuration = $this->client->configuration();

        return PollingLoop::until(
            $this->sleeper,
            $configuration->sessionTimeoutSeconds,
            $configuration->pollTimeoutMs,
            function (int $timeoutMs) use ($session): ?SmartIdSessionStatus {
                $status = $this->client->sessionStatus($session->sessionId, $timeoutMs);

                return $status->isComplete() ? $status : null;
            },
        ) ?? new SmartIdSessionStatus(SmartIdSessionStatus::STATE_COMPLETE, result: SmartIdEndResult::Timeout);
    }

    /**
     * @throws SmartIdSessionException when the person did not complete the session
     */
    public function waitForSuccess(SmartIdSession $session): SmartIdSessionStatus
    {
        return $this->wait($session)->requireOk();
    }
}
