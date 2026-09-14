<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Http;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Http\HttpRequest;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
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

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function urls(): iterable
    {
        $session = 'https://tsp.demo.sk.ee/mid-api/authentication/session/de305d54-75b4-431b-adb2-eb6b9e546014';

        yield 'Smart-ID document number' => [
            'https://rp-api.smart-id.com/v3/signature/certificate/PNOEE-50001029996-MOCK-Q',
            'https://rp-api.smart-id.com/v3/signature/certificate/PNOEE-[redacted]',
        ];
        yield 'semantics identifier' => [
            'https://rp-api.smart-id.com/v3/signature/notification/etsi/PASLT-X1234567',
            'https://rp-api.smart-id.com/v3/signature/notification/etsi/PASLT-[redacted]',
        ];
        yield 'bare identity code' => [
            'https://tsp.demo.sk.ee/mid-api/certificate/60001019906',
            'https://tsp.demo.sk.ee/mid-api/certificate/[redacted]',
        ];
        // Session identifiers tie a line to one attempt, and name nobody.
        yield 'session identifier' => [$session, $session];
        yield 'nothing personal' => ['http://demo.sk.ee/ocsp', 'http://demo.sk.ee/ocsp'];
    }

    #[DataProvider('urls')]
    public function testIdentityCodesAreRemovedWhereverAUrlIsShown(string $url, string $expected): void
    {
        self::assertSame($expected, HttpRequest::get($url)->redactedUrl());
        self::assertSame($expected, HttpRequest::withoutIdentities($url));
    }
}
