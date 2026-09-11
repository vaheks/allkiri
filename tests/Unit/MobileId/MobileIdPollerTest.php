<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\MobileId;

use Allkiri\Crypto\HashAlgorithm;
use Allkiri\MobileId\MobileIdClient;
use Allkiri\MobileId\MobileIdConfiguration;
use Allkiri\MobileId\MobileIdIdentity;
use Allkiri\MobileId\MobileIdPoller;
use Allkiri\MobileId\MobileIdResult;
use Allkiri\MobileId\MobileIdSession;
use Allkiri\MobileId\MobileIdSessionException;
use Allkiri\MobileId\VerificationCode;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Tests\Support\MobileId\MockMobileIdService;
use Allkiri\Tests\Support\MobileId\NullSleeper;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class MobileIdPollerTest extends TestCase
{
    private MockHttpClient $http;

    private MockMobileIdService $service;

    protected function setUp(): void
    {
        $this->http = new MockHttpClient();
        $this->service = MockMobileIdService::register($this->http);
    }

    private function client(int $pollTimeoutMs = 10_000, int $sessionTimeoutSeconds = 120): MobileIdClient
    {
        return new MobileIdClient(
            (new MobileIdConfiguration(MockMobileIdService::URL, MobileIdConfiguration::DEMO_RELYING_PARTY_UUID, 'TEST'))
                ->withTimeouts($pollTimeoutMs, $sessionTimeoutSeconds),
            $this->http,
        );
    }

    private function session(MobileIdClient $client, string $preimage = 'sign me'): MobileIdSession
    {
        $hash = hash('sha256', $preimage, true);
        $this->service->expectToSign($preimage);

        return new MobileIdSession(
            $client->startSignature(self::identity(), $hash, HashAlgorithm::SHA256),
            MobileIdSession::TYPE_SIGNATURE,
            VerificationCode::forHash($hash),
            self::identity(),
        );
    }

    private static function identity(): MobileIdIdentity
    {
        return new MobileIdIdentity('+37200000766', '38001085718');
    }

    public function testItKeepsAskingUntilThePersonIsDone(): void
    {
        $this->service->runningPolls = 4;
        $client = $this->client();
        $session = $this->session($client);
        $sleeper = new NullSleeper();

        $status = (new MobileIdPoller($client, $sleeper))->wait($session);

        self::assertTrue($status->isOk());
        // Four RUNNING answers, then the real one.
        self::assertSame(5, $this->http->requestCount(MockMobileIdService::URL . '/signature/session/'));
    }

    public function testItReturnsAtOnceWhenTheAnswerIsAlreadyThere(): void
    {
        $client = $this->client();
        $session = $this->session($client);
        $sleeper = new NullSleeper();

        (new MobileIdPoller($client, $sleeper))->wait($session);

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

        (new MobileIdPoller($client, $sleeper))->wait($session);

        self::assertCount(3, $sleeper->slept);
        self::assertSame(3.0, $sleeper->total());
    }

    public function testItGivesUpWhenTheSessionBudgetRunsOut(): void
    {
        // The person never answers.
        $this->service->runningPolls = PHP_INT_MAX;
        $client = $this->client(pollTimeoutMs: 10_000, sessionTimeoutSeconds: 30);
        $session = $this->session($client);

        try {
            (new MobileIdPoller($client, new NullSleeper()))->wait($session);
            self::fail('Expected the poller to give up');
        } catch (MobileIdSessionException $exception) {
            self::assertSame(MobileIdResult::Timeout, $exception->result);
        }

        // Three ten-second polls exhaust a thirty-second budget.
        self::assertSame(3, $this->http->requestCount(MockMobileIdService::URL . '/signature/session/'));
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

        try {
            (new MobileIdPoller($client, new NullSleeper()))->wait($session);
        } catch (MobileIdSessionException) {
            // expected
        }

        $timeouts = [];
        foreach ($this->http->requests() as $request) {
            if (preg_match('/timeoutMs=(\d+)/', $request->url, $matches) === 1) {
                $timeouts[] = (int) $matches[1];
            }
        }

        self::assertSame([10_000, 10_000, 5_000], $timeouts);
    }

    /**
     * @return iterable<string, array{MobileIdResult}>
     */
    public static function failures(): iterable
    {
        yield 'cancelled' => [MobileIdResult::UserCancelled];
        yield 'timeout' => [MobileIdResult::Timeout];
        yield 'not a Mobile-ID client' => [MobileIdResult::NotMidClient];
        yield 'phone absent' => [MobileIdResult::PhoneAbsent];
        yield 'delivery error' => [MobileIdResult::DeliveryError];
        yield 'sim error' => [MobileIdResult::SimError];
        yield 'hash mismatch' => [MobileIdResult::SignatureHashMismatch];
    }

    #[DataProvider('failures')]
    public function testItStopsAtOnceOnAnyFailure(MobileIdResult $result): void
    {
        $this->service->result = $result;
        $client = $this->client();
        $session = $this->session($client);

        try {
            (new MobileIdPoller($client, new NullSleeper()))->wait($session);
            self::fail('Expected a MobileIdSessionException');
        } catch (MobileIdSessionException $exception) {
            self::assertSame($result, $exception->result);
            self::assertStringContainsString($result->message(), $exception->getMessage());
        }

        self::assertSame(1, $this->http->requestCount(MockMobileIdService::URL . '/signature/session/'));
    }
}
