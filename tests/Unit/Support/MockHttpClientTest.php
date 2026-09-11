<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Support;

use Allkiri\Http\HttpRequest;
use Allkiri\Http\HttpResponse;
use Allkiri\Http\TransportException;
use Allkiri\Tests\Support\Http\MockHttpClient;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class MockHttpClientTest extends TestCase
{
    public function testLongestPrefixWinsAndRequestsAreRecorded(): void
    {
        $mock = (new MockHttpClient())
            ->respond('http://demo.sk.ee/', 404, 'text/plain', 'generic')
            ->on('http://demo.sk.ee/ocsp', static fn(HttpRequest $r): HttpResponse => new HttpResponse(200, ['Content-Type' => 'application/ocsp-response'], strrev($r->body)));

        $ocsp = $mock->send(HttpRequest::post('http://demo.sk.ee/ocsp', 'application/ocsp-request', 'abc'));
        $other = $mock->send(HttpRequest::get('http://demo.sk.ee/upload_cert/'));

        self::assertSame('cba', $ocsp->body);
        self::assertSame(404, $other->status);
        self::assertSame(2, $mock->requestCount());
        self::assertSame(1, $mock->requestCount('http://demo.sk.ee/ocsp'));
        self::assertSame('http://demo.sk.ee/upload_cert/', $mock->lastRequest()?->url);
    }

    public function testUnroutedRequestIsATransportFailure(): void
    {
        $mock = new MockHttpClient();

        $this->expectException(TransportException::class);

        $mock->send(HttpRequest::get('http://tsa.demo.sk.ee/tsa'));
    }
}
