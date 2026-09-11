<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Http;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Http\CurlHttpClient;
use Allkiri\Http\HttpRequest;
use Allkiri\Http\TransportException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(CurlHttpClient::class)]
final class CurlHttpClientTest extends TestCase
{
    private const PIN_A = 'YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=';
    private const PIN_B = 'sRHdihwgkaib1P1gxX8HFszlD+7/gTfNvuAybgLPNis=';

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
}
