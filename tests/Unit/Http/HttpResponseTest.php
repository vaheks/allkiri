<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Http;

use Allkiri\Http\HttpResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(HttpResponse::class)]
final class HttpResponseTest extends TestCase
{
    public function testHeadersAreNormalisedToLowerCase(): void
    {
        $response = new HttpResponse(200, ['Content-Type' => 'application/timestamp-reply; charset=binary'], 'body');

        self::assertSame(['content-type' => 'application/timestamp-reply; charset=binary'], $response->headers);
        self::assertSame('application/timestamp-reply; charset=binary', $response->header('CONTENT-TYPE'));
        self::assertNull($response->header('etag'));
    }

    public function testContentTypeDropsParametersAndCase(): void
    {
        $response = new HttpResponse(200, ['Content-Type' => 'Application/OCSP-Response ; charset=binary'], '');

        self::assertSame('application/ocsp-response', $response->contentType());
        self::assertNull((new HttpResponse(204, [], ''))->contentType());
    }

    public function testIsSuccessCoversTheWhole2xxRange(): void
    {
        self::assertTrue((new HttpResponse(200, [], ''))->isSuccess());
        self::assertTrue((new HttpResponse(299, [], ''))->isSuccess());
        self::assertFalse((new HttpResponse(199, [], ''))->isSuccess());
        self::assertFalse((new HttpResponse(300, [], ''))->isSuccess());
        self::assertFalse((new HttpResponse(500, [], ''))->isSuccess());
    }
}
