<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Xml;

use Allkiri\Xml\XsdDateTime;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(XsdDateTime::class)]
final class XsdDateTimeTest extends TestCase
{
    /**
     * @param string $text     what a document states
     * @param string $expected the same moment in UTC
     */
    #[DataProvider('statedTimes')]
    public function testAStatedTimeIsRead(string $text, string $expected): void
    {
        $parsed = XsdDateTime::tryParse($text);

        self::assertNotNull($parsed, $text . ' is a time');
        self::assertSame($expected, $parsed->format('Y-m-d\TH:i:s\Z'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function statedTimes(): iterable
    {
        yield 'UTC' => ['2026-09-17T10:30:00Z', '2026-09-17T10:30:00Z'];
        yield 'an offset' => ['2026-09-17T13:30:00+03:00', '2026-09-17T10:30:00Z'];
        yield 'a negative offset' => ['2026-09-17T05:30:00-05:00', '2026-09-17T10:30:00Z'];
        yield 'fractional seconds' => ['2026-09-17T10:30:00.123Z', '2026-09-17T10:30:00Z'];
        yield 'surrounding whitespace' => ["  2026-09-17T10:30:00Z\n", '2026-09-17T10:30:00Z'];
    }

    /**
     * The point of the class. PHP's constructor reads these as times, and a
     * document that could say one of them would be setting the clock rather
     * than stating when something happened.
     *
     * @param string $text what a document might say instead of a time
     */
    #[DataProvider('thingsThatAreNotTimes')]
    public function testWhatIsNotAStatedTimeIsNotRead(string $text): void
    {
        self::assertNull(XsdDateTime::tryParse($text), $text . ' was read as a time');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function thingsThatAreNotTimes(): iterable
    {
        yield 'now' => ['now'];
        yield 'tomorrow' => ['tomorrow'];
        yield 'a relative offset' => ['+1 year'];
        yield 'the epoch shorthand' => ['@0'];
        yield 'first monday' => ['first monday of January 2026'];
        yield 'a date alone' => ['2026-09-17'];
        yield 'a date that does not exist' => ['2026-02-31T00:00:00Z'];
        yield 'a trailing newline inside' => ["2026-09-17T10:30:00Z\nnow"];
        yield 'empty' => [''];
        yield 'nonsense' => ['not a time at all'];
    }

    public function testNothingStatedIsNoTime(): void
    {
        self::assertNull(XsdDateTime::tryParse(null));
    }

    /**
     * "now" would otherwise land a moment either side of the reading, so this
     * would pass by accident if the value were read as a relative format.
     */
    public function testARelativeFormatIsNotReadAsTheMomentOfReading(): void
    {
        $parsed = XsdDateTime::tryParse('now');

        self::assertNull($parsed);
    }
}
