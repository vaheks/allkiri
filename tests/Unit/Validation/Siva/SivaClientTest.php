<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Validation\Siva;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Http\HttpResponse;
use Allkiri\Http\TransportException;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Validation\Siva\SivaClient;
use Allkiri\Validation\Siva\SivaException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(SivaClient::class)]
final class SivaClientTest extends TestCase
{
    private const URL = 'https://siva.allkiri.test/V3/validate';

    /**
     * The whole container goes to this URL, so it is never sent in clear text
     * to anything but this machine.
     */
    public function testAPlainHttpUrlIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The SiVa URL must be an https:// URL');

        new SivaClient(new MockHttpClient(), 'http://siva-demo.eesti.ee/V3/validate');
    }

    public function testASivaOnThisMachineMayBePlainHttp(): void
    {
        $this->expectNotToPerformAssertions();

        new SivaClient(new MockHttpClient(), 'http://localhost:8080/V3/validate');
    }

    /**
     * Usually the name of an upload, so a failure at run time rather than a
     * programmer error. json_encode's JsonException escaped instead.
     */
    public function testAFileNameThatIsNotUtf8IsRefusedBeforeAnythingIsSent(): void
    {
        $http = new MockHttpClient();

        try {
            (new SivaClient($http, self::URL))->validate('container bytes', "leping\xC3.asice");
            self::fail('a file name that is not UTF-8 was sent');
        } catch (SivaException $exception) {
            self::assertSame(SivaException::REASON_REQUEST, $exception->reason);
            self::assertStringContainsString('must be UTF-8', $exception->getMessage());
        }
        self::assertSame([], $http->requests());
    }

    /**
     * RIA put SiVa behind Cloudflare in 2026, which now and then answers a
     * server with a challenge page instead of a verdict. The caller needs to
     * know that it was refused, not read the page.
     */
    public function testACloudflareChallengeIsNamedWithoutItsPage(): void
    {
        $http = (new MockHttpClient())->on(self::URL, static fn(): HttpResponse => new HttpResponse(
            403,
            ['Content-Type' => 'text/html; charset=UTF-8', 'cf-mitigated' => 'challenge', 'Server' => 'cloudflare'],
            '<!DOCTYPE html><html lang="en-US"><head><title>Just a moment...</title></head></html>',
        ));

        $exception = $this->failureOf($http);

        self::assertSame(SivaException::REASON_CHALLENGED, $exception->reason);
        self::assertStringContainsString('challenge', $exception->getMessage());
        self::assertStringContainsString('HTTP 403', $exception->getMessage());
        self::assertStringNotContainsString('<!DOCTYPE', $exception->getMessage());
        self::assertSame(1, $http->requestCount(), 'the client does not retry on its own');
    }

    public function testAnyOtherRefusalCarriesItsStatus(): void
    {
        $http = (new MockHttpClient())->respond(self::URL, 500, 'application/json', '{"error":"internal"}');

        $exception = $this->failureOf($http);

        self::assertSame(SivaException::REASON_HTTP_STATUS, $exception->reason);
        self::assertStringContainsString('SiVa answered HTTP 500', $exception->getMessage());
    }

    public function testAnUnreachableSivaIsATransportFailure(): void
    {
        $http = (new MockHttpClient())->on(self::URL, static fn(): never => throw new TransportException('connection refused'));

        $exception = $this->failureOf($http);

        self::assertSame(SivaException::REASON_TRANSPORT, $exception->reason);
        self::assertStringContainsString('connection refused', $exception->getMessage());
        self::assertInstanceOf(TransportException::class, $exception->getPrevious());
    }

    public function testAnAnswerThatIsNotJsonIsMalformed(): void
    {
        $http = (new MockHttpClient())->respond(self::URL, 200, 'text/html', '<html>maintenance</html>');

        self::assertSame(SivaException::REASON_MALFORMED, $this->failureOf($http)->reason);
    }

    public function testJsonWithoutAConclusionIsMalformed(): void
    {
        $http = (new MockHttpClient())->respond(self::URL, 200, 'application/json', '{"validationReport":{}}');

        self::assertSame(SivaException::REASON_MALFORMED, $this->failureOf($http)->reason);
    }

    private function failureOf(MockHttpClient $http): SivaException
    {
        try {
            (new SivaClient($http, self::URL))->validate('container bytes', 'leping.asice');
        } catch (SivaException $exception) {
            return $exception;
        }

        self::fail('SiVa\'s answer was accepted');
    }
}
