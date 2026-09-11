<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Http;

use Allkiri\Http\HttpRequest;
use Allkiri\Http\Psr18HttpClient;
use Allkiri\Http\TransportException;
use GuzzleHttp\Psr7\HttpFactory;
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
}
