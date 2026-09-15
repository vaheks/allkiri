<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\WebEid;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\WebEid\WebEidOrigin;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;

/**
 * The origin is half of what a card signs at sign-in, and the token does not
 * carry it, so the configured value has to come out exactly as the browser's
 * `location.origin`: one spelling for every way of writing the same site, and a
 * refusal for anything that is not an origin.
 *
 * Without intl, a host that is not ASCII is refused with a message saying so.
 * That path is not tested here, because the suite runs with intl loaded.
 */
#[CoversNothing]
final class WebEidOriginTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function accepted(): iterable
    {
        yield 'an origin as a browser reports it' => ['https://example.ee', 'https://example.ee'];
        yield 'the default port, which a browser leaves out' => ['https://example.ee:443', 'https://example.ee'];
        yield 'another port, which it keeps' => ['https://example.ee:8443', 'https://example.ee:8443'];
        yield 'a host in capitals' => ['https://Teenus.Example.EE', 'https://teenus.example.ee'];
        yield 'a scheme in capitals' => ['HTTPS://example.ee', 'https://example.ee'];
        yield 'a trailing slash' => ['https://example.ee/', 'https://example.ee'];
        yield 'surrounding whitespace' => ["  https://example.ee\n", 'https://example.ee'];
        yield 'a hyphen and digits in the host' => ['https://e-teenus24.example.ee', 'https://e-teenus24.example.ee'];
    }

    #[DataProvider('accepted')]
    public function testAnOriginIsWrittenAsTheBrowserWritesIt(string $configured, string $expected): void
    {
        $origin = WebEidOrigin::parse($configured);

        self::assertSame($expected, $origin->value);
        self::assertSame($expected, (string) $origin);
    }

    #[RequiresPhpExtension('intl')]
    public function testAnInternationalisedHostIsWrittenInPunycode(): void
    {
        self::assertSame('https://xn--pike-loa.ee', WebEidOrigin::parse("https://p\u{e4}ike.ee")->value);
        self::assertSame('https://xn--pike-loa.ee:8443', WebEidOrigin::parse("https://P\u{c4}IKE.ee:8443")->value);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function refused(): iterable
    {
        yield 'nothing' => ['', 'The site origin must not be empty'];
        yield 'only whitespace' => [" \t ", 'The site origin must not be empty'];
        yield 'a host without a scheme' => ['example.ee', '"example.ee" is not an origin such as https://example.ee'];
        yield 'a port past 65535' => ['https://example.ee:65536', 'is not an origin such as https://example.ee'];
        yield 'plain http' => ['http://example.ee', 'The site origin must use https, got "http"'];
        yield 'another scheme' => ['wss://example.ee', 'The site origin must use https, got "wss"'];
        yield 'a user' => ['https://user@example.ee', 'The site origin must be only the scheme, host and optional port'];
        yield 'a user and a password' => ['https://user:secret@example.ee', 'The site origin must be only the scheme, host and optional port'];
        yield 'a query' => ['https://example.ee/?next=/', 'The site origin must be only the scheme, host and optional port'];
        yield 'a fragment' => ['https://example.ee#top', 'The site origin must be only the scheme, host and optional port'];
        yield 'a path' => ['https://example.ee/login', 'The site origin must carry no path, got "/login"'];
        yield 'port zero' => ['https://example.ee:0', 'The site origin port must be between 1 and 65535'];
    }

    #[DataProvider('refused')]
    public function testAnythingButAnOriginIsRefused(string $configured, string $message): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        WebEidOrigin::parse($configured);
    }

    #[RequiresPhpExtension('intl')]
    public function testAHostPunycodeCannotWriteIsRefused(): void
    {
        // A DNS label holds at most 63 characters, and this one would need more.
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('cannot be converted to Punycode');

        WebEidOrigin::parse('https://' . str_repeat("\u{e4}", 64) . '.ee');
    }
}
