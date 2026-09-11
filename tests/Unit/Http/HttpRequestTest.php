<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Http;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Http\HttpRequest;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(HttpRequest::class)]
final class HttpRequestTest extends TestCase
{
    public function testGetHasNoBody(): void
    {
        $request = HttpRequest::get('https://example.test/tsl.xml', ['Accept' => 'application/xml']);

        self::assertSame('GET', $request->method);
        self::assertSame('https://example.test/tsl.xml', $request->url);
        self::assertSame('', $request->body);
        self::assertSame('application/xml', $request->header('accept'));
    }

    public function testPostSetsContentType(): void
    {
        $request = HttpRequest::post('http://demo.sk.ee/ocsp', 'application/ocsp-request', "\x30\x03\x02\x01\x00");

        self::assertSame('POST', $request->method);
        self::assertSame('application/ocsp-request', $request->header('Content-Type'));
        self::assertSame("\x30\x03\x02\x01\x00", $request->body);
    }

    public function testHeaderLookupIsCaseInsensitiveAndNullWhenAbsent(): void
    {
        $request = HttpRequest::get('https://example.test/', ['X-Trace' => 'abc']);

        self::assertSame('abc', $request->header('x-trace'));
        self::assertNull($request->header('Authorization'));
    }

    public function testRejectsNonHttpUrls(): void
    {
        $this->expectException(InvalidArgumentException::class);

        HttpRequest::get('ftp://example.test/file');
    }
}
