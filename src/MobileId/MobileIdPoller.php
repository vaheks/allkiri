<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

use Allkiri\Clock\PollingLoop;
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
     * A status request that could not reach the service is asked again, up to
     * three failures in a row, within the session timeout.
     *
     * @throws MobileIdSessionException when the person did not complete the session, or the timeout passed first
     * @throws MobileIdApiException     when the service could not be reached three times in a row, or answered with an error
     */
    public function wait(MobileIdSession $session): MobileIdSessionStatus
    {
        $configuration = $this->client->configuration();
        $status = PollingLoop::until(
            $this->sleeper,
            $configuration->sessionTimeoutSeconds,
            $configuration->pollTimeoutMs,
            function (int $timeoutMs) use ($session): ?MobileIdSessionStatus {
                $status = $this->client->status($session->type, $session->sessionId, $timeoutMs);

                return $status->isComplete() ? $status : null;
            },
            static fn(\Throwable $e): bool => $e instanceof MobileIdApiException && $e->reason === MobileIdApiException::REASON_TRANSPORT,
        ) ?? throw new MobileIdSessionException(MobileIdResult::Timeout);

        if (!$status->isOk()) {
            throw new MobileIdSessionException($status->result ?? MobileIdResult::Timeout);
        }

        return $status;
    }
}
