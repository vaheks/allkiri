<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Container;

use Allkiri\Container\AsicContainer;
use Allkiri\Container\AsicReader;
use Allkiri\Container\DataFile;
use Allkiri\Container\Manifest;
use Allkiri\Container\Zip\InflationLimit;
use Allkiri\Container\Zip\ZipEntry;
use Allkiri\Container\Zip\ZipReader;
use Allkiri\Container\Zip\ZipWriter;
use Allkiri\Container\ZipBombException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * What a container is allowed to expand to when it is read.
 *
 * A few hundred kilobytes can declare hundreds of megabytes, and an
 * application that validates uploads would hold all of it before discovering
 * there was nothing there. The limits are digidoc4j's, so the two libraries
 * refuse the same archives.
 */
#[CoversClass(InflationLimit::class)]
final class InflationLimitTest extends TestCase
{
    /** 20 MB of zeros compresses to about 20 KB: a ratio of roughly 1000 to 1. */
    private const BOMB_BYTES = 20 * 1024 * 1024;

    /**
     * @param array<string, string> $files name => content, deflated
     */
    private static function container(array $files): string
    {
        $writer = (new ZipWriter())->addStored('mimetype', AsicContainer::MIME_TYPE);
        $dataFiles = [];
        foreach ($files as $name => $content) {
            $writer = $writer->addDeflated($name, $content);
            $dataFiles[] = DataFile::fromString($name, '');
        }

        return $writer->addDeflated('META-INF/manifest.xml', Manifest::forDataFiles($dataFiles)->toXml())->build();
    }

    // --- refusing ------------------------------------------------------------

    public function testAContainerThatWouldExpandOutOfAllProportionIsRefused(): void
    {
        $bomb = self::container(['bomb.bin' => str_repeat("\0", self::BOMB_BYTES)]);
        self::assertLessThan(100_000, \strlen($bomb), 'the bomb should be small on disk');

        $this->expectException(ZipBombException::class);
        $this->expectExceptionMessageMatches('/Refusing to decompress it/');

        (new AsicReader())->read($bomb);
    }

    /**
     * The declared size is checked first because it is free, but an archive can
     * lie about it. Then the only defence is to count while decompressing and
     * stop, which is what digidoc4j does as it streams.
     */
    public function testAnEntryThatLiesAboutItsSizeIsStillRefusedWhileDecompressing(): void
    {
        $packed = gzdeflate(str_repeat("\0", self::BOMB_BYTES));
        self::assertIsString($packed);

        $limit = new InflationLimit(\strlen($packed));

        $this->expectException(ZipBombException::class);
        $this->expectExceptionMessageMatches('/expands past/');

        // Claiming one byte gets it past the cheap check and no further.
        $limit->inflate('liar.bin', $packed, 1);
    }

    /**
     * The guard has to cost less memory than the attack, or it is not a guard.
     */
    public function testRefusingCostsFarLessMemoryThanGivingIn(): void
    {
        $packed = gzdeflate(str_repeat("\0", self::BOMB_BYTES));
        self::assertIsString($packed);
        $limit = new InflationLimit(\strlen($packed));
        $allowed = $limit->total();

        gc_collect_cycles();
        memory_reset_peak_usage();
        $before = memory_get_usage(true);
        try {
            $limit->inflate('bomb.bin', $packed, 1);
            self::fail('the bomb should have been refused');
        } catch (ZipBombException) {
            $peak = memory_get_peak_usage(true) - $before;
        }

        // Bounded by what the container was allowed, not by what it wanted:
        // 20 MB of payload against an allowance of about 2 MB.
        self::assertLessThan(self::BOMB_BYTES, $peak, 'refusing should cost less than the payload');
        self::assertGreaterThan($allowed, self::BOMB_BYTES, 'the payload should exceed the allowance for this to mean anything');
    }

    public function testTheBudgetIsSharedAcrossEntriesRatherThanPerEntry(): void
    {
        // Each half fits on its own; together they do not.
        $packed = gzdeflate(str_repeat("\0", self::BOMB_BYTES));
        self::assertIsString($packed);
        $limit = new InflationLimit(\strlen($packed) * 2, maxRatio: 2);
        $allowance = $limit->total();

        $first = str_repeat('a', intdiv($allowance, 2));
        $second = str_repeat('b', intdiv($allowance, 2) + 1000);

        $limit->inflate('one', (string) gzdeflate($first), \strlen($first));

        $this->expectException(ZipBombException::class);

        $limit->inflate('two', (string) gzdeflate($second), \strlen($second));
    }

    public function testReadingOneEntryTwiceIsNotChargedTwice(): void
    {
        $content = str_repeat('a', 900_000);
        $packed = (string) gzdeflate($content);
        $limit = new InflationLimit(\strlen($packed), maxRatio: 2);

        self::assertSame($content, $limit->inflate('one', $packed, \strlen($content)));
        self::assertSame($content, $limit->inflate('one', $packed, \strlen($content)), 'the same entry again');
    }

    // --- letting ordinary containers through ---------------------------------

    public function testAnOrdinaryContainerIsNotDisturbed(): void
    {
        // Text compresses well, nowhere near a hundred to one.
        $text = str_repeat("Tere, allkiri! See on tavaline dokument.\n", 5000);
        $container = self::container(['leping.txt' => $text]);

        $read = (new AsicReader())->read($container);

        self::assertSame($text, $read->dataFiles[0]->content);
    }

    /**
     * Below the threshold the ratio is not consulted at all, so a small file of
     * zeros is fine however well it compresses.
     */
    public function testSmallFilesAreNeverQuestioned(): void
    {
        $container = self::container(['small.bin' => str_repeat("\0", 500_000)]);

        $read = (new AsicReader())->read($container);

        self::assertSame(500_000, \strlen($read->dataFiles[0]->content));
    }

    public function testTheLimitsAreConfigurable(): void
    {
        $bomb = self::container(['bomb.bin' => str_repeat("\0", self::BOMB_BYTES)]);

        // Refused by default, accepted when the caller says so.
        $read = (new AsicReader(maxCompressionRatio: 5000))->read($bomb);

        self::assertSame(self::BOMB_BYTES, \strlen($read->dataFiles[0]->content));
    }

    public function testTheLimitCanBeTurnedOffEntirely(): void
    {
        $packed = gzdeflate(str_repeat("\0", self::BOMB_BYTES));
        self::assertIsString($packed);

        $inflated = InflationLimit::none()->inflate('bomb.bin', $packed, self::BOMB_BYTES);

        self::assertSame(self::BOMB_BYTES, \strlen($inflated));
    }

    /**
     * Entries this library builds itself carry no budget, so writing and reading
     * back what we just wrote cannot trip over it.
     */
    public function testAnEntryWithNoLimitInflatesFreely(): void
    {
        $content = str_repeat("\0", self::BOMB_BYTES);
        $entry = new ZipEntry('x.bin', ZipEntry::METHOD_DEFLATE, 0, crc32($content), 0, \strlen($content), 0, 0, (string) gzdeflate($content));

        self::assertSame($content, $entry->content());
    }

    public function testCorruptDataIsReportedAsCorruptRatherThanHostile(): void
    {
        $this->expectExceptionMessageMatches('/could not be decompressed/');

        (new InflationLimit(1000))->inflate('broken.bin', 'this is not deflate data', 10);
    }

    public function testTheReaderPassesItsOwnSizeAsTheBasis(): void
    {
        $container = self::container(['a.txt' => str_repeat('a', 2000)]);
        $entries = ZipReader::read($container);

        $entry = null;
        foreach ($entries as $candidate) {
            if ($candidate->name === 'a.txt') {
                $entry = $candidate;
            }
        }
        self::assertNotNull($entry);
        self::assertNotNull($entry->limit);
        self::assertSame(max(InflationLimit::DEFAULT_THRESHOLD_BYTES, \strlen($container) * 100), $entry->limit->total());
    }
}
