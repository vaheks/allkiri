<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Http;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Http\HttpRequest;
use Allkiri\Http\Psr18HttpClient;
use Allkiri\Http\TransportException;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\PumpStream;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

#[CoversClass(Psr18HttpClient::class)]
final class Psr18HttpClientTest extends TestCase
{
    public function testRequestIsTranslatedAndResponseMappedBack(): void
    {
        $psr = new class implements ClientInterface {
            public ?RequestInterface $seen = null;

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                $this->seen = $request;

                return new Response(200, ['Content-Type' => ['application/ocsp-response'], 'X-Multi' => ['a', 'b']], 'payload');
            }
        };
        $factory = new HttpFactory();
        $client = new Psr18HttpClient($psr, $factory, $factory);

        $response = $client->send(HttpRequest::post('https://example.test/ocsp', 'application/ocsp-request', 'req-bytes', ['X-Trace' => 't1']));

        $seen = $psr->seen;
        self::assertInstanceOf(RequestInterface::class, $seen);
        self::assertSame('POST', $seen->getMethod());
        self::assertSame('https://example.test/ocsp', (string) $seen->getUri());
        self::assertSame('application/ocsp-request', $seen->getHeaderLine('Content-Type'));
        self::assertSame('t1', $seen->getHeaderLine('X-Trace'));
        self::assertSame('req-bytes', (string) $seen->getBody());

        self::assertSame(200, $response->status);
        self::assertSame('application/ocsp-response', $response->contentType());
        self::assertSame('a, b', $response->header('x-multi'));
        self::assertSame('payload', $response->body);
    }

    public function testClientExceptionBecomesTransportException(): void
    {
        $psr = new class implements ClientInterface {
            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                throw new class ('boom') extends \RuntimeException implements ClientExceptionInterface {};
            }
        };
        $factory = new HttpFactory();
        $client = new Psr18HttpClient($psr, $factory, $factory);

        $this->expectException(TransportException::class);
        $this->expectExceptionMessage('boom');

        $client->send(HttpRequest::get('https://example.test/'));
    }

    // --- the size of an answer ----------------------------------------------

    private static function answering(ResponseInterface $response, int $maxResponseBytes = 1000): Psr18HttpClient
    {
        $psr = new class ($response) implements ClientInterface {
            public function __construct(private readonly ResponseInterface $response) {}

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                return $this->response;
            }
        };
        $factory = new HttpFactory();

        return new Psr18HttpClient($psr, $factory, $factory, $maxResponseBytes);
    }

    public function testAnAnswerOfExactlyTheLimitIsAccepted(): void
    {
        $response = self::answering(new Response(200, [], str_repeat('x', 1000)))->send(HttpRequest::get('https://example.test/tl.xml'));

        self::assertSame(str_repeat('x', 1000), $response->body);
    }

    /**
     * A body that knows its size is refused without being read, which this one
     * proves by throwing if it is.
     */
    public function testAnAnswerThatAnnouncesTooLargeASizeIsRefusedUnread(): void
    {
        $unread = new PumpStream(static function (): never {
            throw new \LogicException('the body was read');
        }, ['size' => 1001]);

        $this->expectException(TransportException::class);
        $this->expectExceptionMessage('GET https://example.test/tl.xml answered with more than the 1000 bytes this client accepts');

        self::answering(new Response(200, [], $unread))->send(HttpRequest::get('https://example.test/tl.xml'));
    }

    /**
     * A body of unknown size is read only as far as the limit. This one never
     * ends, so reading it all would never return.
     */
    public function testAnEndlessAnswerIsRefusedAtTheLimit(): void
    {
        $endless = new PumpStream(static fn(int $length): string => str_repeat('x', max(0, $length)));

        $this->expectException(TransportException::class);
        $this->expectExceptionMessage('answered with more than the 1000 bytes this client accepts');

        self::answering(new Response(200, [], $endless))->send(HttpRequest::get('https://example.test/tl.xml'));
    }

    public function testABodyThatBreaksOffIsATransportFailure(): void
    {
        $broken = new PumpStream(static function (): never {
            throw new \RuntimeException('Connection reset by peer');
        });

        $this->expectException(TransportException::class);
        $this->expectExceptionMessage('the answer could not be read: Connection reset by peer (RuntimeException)');

        self::answering(new Response(200, [], $broken))->send(HttpRequest::get('https://example.test/tl.xml'));
    }

    public function testTheLimitMustBeAtLeastOneByte(): void
    {
        $this->expectException(InvalidArgumentException::class);

        self::answering(new Response(), 0);
    }
}
