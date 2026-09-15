<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\SmartId;

use Allkiri\SmartId\DocumentNumber;
use Allkiri\SmartId\Interaction;
use Allkiri\SmartId\Interactions;
use Allkiri\SmartId\SmartIdClient;
use Allkiri\SmartId\SmartIdEndResult;
use Allkiri\SmartId\SmartIdPoller;
use Allkiri\SmartId\SmartIdSession;
use Allkiri\SmartId\SmartIdSessionException;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Tests\Support\MobileId\NullSleeper;
use Allkiri\Tests\Support\SmartId\MockSmartIdService;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The loop Mobile-ID waits with, except that the Smart-ID poller returns what
 * the session ended with instead of throwing; `waitForSuccess()` throws.
 */
#[CoversNothing]
final class SmartIdPollerTest extends TestCase
{
    private const STATUS_URL = MockSmartIdService::URL . '/session/';

    private MockHttpClient $http;

    private MockSmartIdService $service;

    protected function setUp(): void
    {
        $this->http = new MockHttpClient();
        $this->service = MockSmartIdService::register($this->http);
    }

    private function client(int $pollTimeoutMs = 10_000, int $sessionTimeoutSeconds = 120): SmartIdClient
    {
        return new SmartIdClient($this->service->configuration()->withTimeouts($pollTimeoutMs, $sessionTimeoutSeconds), $this->http);
    }

    private function session(SmartIdClient $client): SmartIdSession
    {
        $challenge = random_bytes(64);
        $interactions = Interactions::of(Interaction::displayTextAndPin('Log in'));

        return new SmartIdSession(
            $client->startNotificationAuthentication(new DocumentNumber(MockSmartIdService::DOCUMENT_NUMBER), $challenge, $interactions),
            SmartIdSession::TYPE_AUTHENTICATION,
            $challenge,
            $interactions,
        );
    }

    public function testItKeepsAskingUntilThePersonIsDone(): void
    {
        $this->service->runningPolls = 4;
        $client = $this->client();
        $session = $this->session($client);

        $status = (new SmartIdPoller($client, new NullSleeper()))->wait($session);

        self::assertTrue($status->isOk());
        // Four RUNNING answers, then the real one.
        self::assertSame(5, $this->http->requestCount(self::STATUS_URL));
    }

    public function testItReturnsAtOnceWhenTheAnswerIsAlreadyThere(): void
    {
        $client = $this->client();
        $session = $this->session($client);
        $sleeper = new NullSleeper();

        (new SmartIdPoller($client, $sleeper))->wait($session);

        self::assertSame([], $sleeper->slept, 'nothing should have been waited for');
    }

    /**
     * The service normally holds each request open. A service that answers
     * immediately must not turn this into a hot loop.
     */
    public function testItPausesBetweenAnswersThatComeBackInstantly(): void
    {
        $this->service->runningPolls = 3;
        $client = $this->client();
        $session = $this->session($client);
        $sleeper = new NullSleeper();

        (new SmartIdPoller($client, $sleeper))->wait($session);

        self::assertCount(3, $sleeper->slept);
        self::assertSame(3.0, $sleeper->total());
    }

    public function testItReturnsATimeoutWhenTheSessionBudgetRunsOut(): void
    {
        // The person never answers.
        $this->service->runningPolls = PHP_INT_MAX;
        $client = $this->client(pollTimeoutMs: 10_000, sessionTimeoutSeconds: 30);
        $session = $this->session($client);

        $status = (new SmartIdPoller($client, new NullSleeper()))->wait($session);

        self::assertTrue($status->isComplete());
        self::assertFalse($status->isOk());
        self::assertSame(SmartIdEndResult::Timeout, $status->result);
        // Three ten-second polls exhaust a thirty-second budget.
        self::assertSame(3, $this->http->requestCount(self::STATUS_URL));
    }

    /**
     * The last poll must not ask the service to wait past the caller's own
     * deadline.
     */
    public function testTheLastPollIsShortenedToFitTheBudget(): void
    {
        $this->service->runningPolls = PHP_INT_MAX;
        $client = $this->client(pollTimeoutMs: 10_000, sessionTimeoutSeconds: 25);
        $session = $this->session($client);

        (new SmartIdPoller($client, new NullSleeper()))->wait($session);

        $timeouts = [];
        foreach ($this->http->requests() as $request) {
            if (str_starts_with($request->url, self::STATUS_URL) && preg_match('/timeoutMs=(\d+)/', $request->url, $matches) === 1) {
                $timeouts[] = (int) $matches[1];
            }
        }

        self::assertSame([10_000, 10_000, 5_000], $timeouts);
    }

    /**
     * @return iterable<string, array{SmartIdEndResult}>
     */
    public static function refusals(): iterable
    {
        yield 'refused' => [SmartIdEndResult::UserRefused];
        yield 'timed out at the service' => [SmartIdEndResult::Timeout];
    }

    #[DataProvider('refusals')]
    public function testARefusalIsReturnedAtOnceNotThrown(SmartIdEndResult $result): void
    {
        $this->service->endResult = $result;
        $client = $this->client();
        $session = $this->session($client);

        $status = (new SmartIdPoller($client, new NullSleeper()))->wait($session);

        self::assertSame($result, $status->result);
        self::assertSame(1, $this->http->requestCount(self::STATUS_URL));
    }

    public function testWaitForSuccessThrowsOnARefusalAndOnATimeout(): void
    {
        $this->service->endResult = SmartIdEndResult::UserRefused;
        $client = $this->client(pollTimeoutMs: 10_000, sessionTimeoutSeconds: 10);

        try {
            (new SmartIdPoller($client, new NullSleeper()))->waitForSuccess($this->session($client));
            self::fail('A refusal was taken for success');
        } catch (SmartIdSessionException $exception) {
            self::assertSame(SmartIdEndResult::UserRefused, $exception->result);
        }

        $this->service->runningPolls = PHP_INT_MAX;

        try {
            (new SmartIdPoller($client, new NullSleeper()))->waitForSuccess($this->session($client));
            self::fail('A session that never finished was taken for success');
        } catch (SmartIdSessionException $exception) {
            self::assertSame(SmartIdEndResult::Timeout, $exception->result);
        }
    }
}
