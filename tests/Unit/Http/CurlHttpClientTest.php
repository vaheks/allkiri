<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Http;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Http\CurlHttpClient;
use Allkiri\Http\HttpClient;
use Allkiri\Http\HttpRequest;
use Allkiri\Http\TransportException;
use Allkiri\Http\UserAgent;
use Allkiri\Tests\Support\Http\LocalHttpServer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(CurlHttpClient::class)]
final class CurlHttpClientTest extends TestCase
{
    private const PIN_A = 'YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=';
    private const PIN_B = 'sRHdihwgkaib1P1gxX8HFszlD+7/gTfNvuAybgLPNis=';

    private static ?LocalHttpServer $server = null;

    public static function setUpBeforeClass(): void
    {
        self::$server = LocalHttpServer::start();
    }

    public static function tearDownAfterClass(): void
    {
        self::$server?->stop();
        self::$server = null;
    }

    private static function local(string $path): string
    {
        return (self::$server ?? throw new \LogicException('The local server is not running'))->url . $path;
    }

    public function testPinsAreRenderedInCurlSyntax(): void
    {
        self::assertSame(
            'sha256//' . self::PIN_A . ';sha256//' . self::PIN_B,
            CurlHttpClient::pinnedPublicKeyOption([self::PIN_A, 'sha256//' . self::PIN_B]),
        );
    }

    public function testMalformedPinIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new CurlHttpClient(pinnedPublicKeys: ['not-a-hash']);
    }

    public function testZeroTimeoutIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new CurlHttpClient(timeoutSeconds: 0);
    }

    public function testConnectionFailureBecomesTransportException(): void
    {
        $client = new CurlHttpClient(timeoutSeconds: 2);

        $this->expectException(TransportException::class);

        // Port 9 (discard) on the loopback address is never listening; the
        // connection is refused immediately, so no network is needed.
        $client->send(HttpRequest::get('http://127.0.0.1:9/'));
    }

    // --- the size of an answer ----------------------------------------------

    /**
     * @return iterable<string, array{string}>
     */
    public static function answers(): iterable
    {
        yield 'with a Content-Length' => ['bytes'];
        yield 'without one' => ['stream'];
    }

    #[DataProvider('answers')]
    public function testAnAnswerOfExactlyTheLimitIsAccepted(string $answer): void
    {
        $client = new CurlHttpClient(timeoutSeconds: 5, maxResponseBytes: 1000);

        $response = $client->send(HttpRequest::get(self::local('/' . $answer . '/1000')));

        self::assertSame(200, $response->status);
        self::assertSame(str_repeat('x', 1000), $response->body);
    }

    /**
     * With a length, cURL refuses before reading; without one, the client
     * stops reading at the limit. Either way the call fails rather than
     * returning a body cut short.
     */
    #[DataProvider('answers')]
    public function testAnAnswerOverTheLimitIsRefused(string $answer): void
    {
        $client = new CurlHttpClient(timeoutSeconds: 5, maxResponseBytes: 1000);

        $this->expectException(TransportException::class);
        $this->expectExceptionMessage('answered with more than the 1000 bytes this client accepts');

        $client->send(HttpRequest::get(self::local('/' . $answer . '/1001')));
    }

    // --- the User-Agent -----------------------------------------------------

    public function testTheInstalledVersionIsSentByDefault(): void
    {
        $response = (new CurlHttpClient(timeoutSeconds: 5))->send(HttpRequest::get(self::local('/user-agent')));

        self::assertSame(UserAgent::default(), $response->body);
    }

    public function testAGivenUserAgentIsSentInstead(): void
    {
        $response = (new CurlHttpClient(timeoutSeconds: 5, userAgent: 'my-app/2.0'))->send(HttpRequest::get(self::local('/user-agent')));

        self::assertSame('my-app/2.0', $response->body);
    }

    // --- limits that cannot work ---------------------------------------------

    /**
     * @return iterable<string, array{int, int|null, int}>
     */
    public static function unworkableLimits(): iterable
    {
        yield 'no time to connect' => [30, 0, HttpClient::DEFAULT_MAX_RESPONSE_BYTES];
        yield 'longer to connect than the whole call' => [30, 31, HttpClient::DEFAULT_MAX_RESPONSE_BYTES];
        yield 'no answer at all' => [30, null, 0];
        yield 'more than cURL can count on Windows' => [30, null, 2_147_483_648];
    }

    #[DataProvider('unworkableLimits')]
    public function testLimitsThatCannotWorkAreRefused(int $timeoutSeconds, ?int $connectTimeoutSeconds, int $maxResponseBytes): void
    {
        $this->expectException(InvalidArgumentException::class);

        new CurlHttpClient(timeoutSeconds: $timeoutSeconds, connectTimeoutSeconds: $connectTimeoutSeconds, maxResponseBytes: $maxResponseBytes);
    }

    public function testConnectingMayTakeTheWholeTimeout(): void
    {
        $this->expectNotToPerformAssertions();

        new CurlHttpClient(timeoutSeconds: 5, connectTimeoutSeconds: 5, maxResponseBytes: 1);
    }
}
