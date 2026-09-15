<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Validation\Siva;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Validation\Siva\SivaClient;
use Allkiri\Validation\Siva\SivaException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(SivaClient::class)]
final class SivaClientTest extends TestCase
{
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
            (new SivaClient($http, 'https://siva.allkiri.test/V3/validate'))->validate('container bytes', "leping\xC3.asice");
            self::fail('a file name that is not UTF-8 was sent');
        } catch (SivaException $exception) {
            self::assertStringContainsString('must be UTF-8', $exception->getMessage());
        }
        self::assertSame([], $http->requests());
    }
}
