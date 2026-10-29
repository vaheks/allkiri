<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\MobileId;

use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Http\HttpRequest;
use Allkiri\Http\HttpResponse;
use Allkiri\Http\TransportException;
use Allkiri\MobileId\MobileIdApiException;
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
    private const STATUS_URL = MockMobileIdService::URL . '/signature/session/';

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

    /**
     * Put the status requests through a script before the mock service sees
     * them: 'down' cannot reach it, 'refused' is answered HTTP 401, and 'up'
     * passes the request on, as every request after the script does.
     */
    private function scriptStatusRequests(string ...$script): void
    {
        $this->http->on(self::STATUS_URL, function (HttpRequest $request) use (&$script): HttpResponse {
            return match (array_shift($script) ?? 'up') {
                'down' => throw new TransportException('Failed to connect to mid.allkiri.test port 443 after 10002 ms: Timeout was reached (curl error 28)'),
                'refused' => new HttpResponse(401, ['Content-Type' => 'application/json'], '{}'),
                default => $this->service->handle($request),
            };
        });
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

    // --- the service out of reach -------------------------------------------

    public function testAStatusRequestThatCouldNotReachTheServiceIsAskedAgain(): void
    {
        $this->scriptStatusRequests('down', 'down');
        $client = $this->client();
        $session = $this->session($client);

        $status = (new MobileIdPoller($client, new NullSleeper()))->wait($session);

        self::assertTrue($status->isOk());
        self::assertSame(3, $this->http->requestCount(self::STATUS_URL));
    }

    public function testThreeFailuresInARowAreThrown(): void
    {
        $this->scriptStatusRequests('down', 'down', 'down');
        $client = $this->client();
        $session = $this->session($client);

        try {
            (new MobileIdPoller($client, new NullSleeper()))->wait($session);
            self::fail('A service out of reach three times in a row was waited for');
        } catch (MobileIdApiException $exception) {
            self::assertSame(MobileIdApiException::REASON_TRANSPORT, $exception->reason);
        }

        self::assertSame(3, $this->http->requestCount(self::STATUS_URL));
    }

    public function testOnlyFailuresInARowAreCounted(): void
    {
        $this->service->runningPolls = 1;
        $this->scriptStatusRequests('down', 'down', 'up', 'down', 'down');
        $client = $this->client();
        $session = $this->session($client);

        $status = (new MobileIdPoller($client, new NullSleeper()))->wait($session);

        self::assertTrue($status->isOk());
        self::assertSame(6, $this->http->requestCount(self::STATUS_URL));
    }

    /**
     * A network outage that outlasts the session is not the person not
     * answering, so it must not come back as TIMEOUT.
     */
    public function testABudgetSpentOutOfReachIsThrownNotTakenForATimeout(): void
    {
        $this->service->runningPolls = PHP_INT_MAX;
        $this->scriptStatusRequests('up', 'down');
        $client = $this->client(pollTimeoutMs: 10_000, sessionTimeoutSeconds: 20);
        $session = $this->session($client);

        try {
            (new MobileIdPoller($client, new NullSleeper()))->wait($session);
            self::fail('A session that could not be asked about was taken for a timeout');
        } catch (MobileIdApiException $exception) {
            self::assertSame(MobileIdApiException::REASON_TRANSPORT, $exception->reason);
        }

        self::assertSame(2, $this->http->requestCount(self::STATUS_URL));
    }

    public function testAnErrorTheServiceAnsweredWithIsThrownAtOnce(): void
    {
        $this->scriptStatusRequests('refused');
        $client = $this->client();
        $session = $this->session($client);

        try {
            (new MobileIdPoller($client, new NullSleeper()))->wait($session);
            self::fail('An HTTP 401 was asked again');
        } catch (MobileIdApiException $exception) {
            self::assertSame(MobileIdApiException::REASON_UNAUTHORISED, $exception->reason);
        }

        self::assertSame(1, $this->http->requestCount(self::STATUS_URL));
    }
}
