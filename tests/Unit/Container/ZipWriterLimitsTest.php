<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Container;

use Allkiri\Container\Zip\UnsupportedZipException;
use Allkiri\Container\Zip\ZipEntry;
use Allkiri\Container\Zip\ZipWriter;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * What the writer refuses to write.
 *
 * Sizes go into 32-bit fields and the entry count into a 16-bit one, so
 * anything larger silently becomes a different number and the archive is
 * quietly corrupt. ZIP64 exists for exactly this and is deliberately not
 * implemented here, which the reader already says out loud; these are the
 * writer saying the same thing rather than producing rubbish.
 */
#[CoversClass(ZipWriter::class)]
final class ZipWriterLimitsTest extends TestCase
{
    private const UINT32_MAX = 0xFFFFFFFF;

    public function testMoreEntriesThanTheFormatCanCountAreRefused(): void
    {
        $writer = new ZipWriter();
        for ($i = 0; $i <= 0xFFFF; ++$i) {
            $writer = $writer->addStored(\sprintf('f%d.txt', $i), 'x');
        }

        $this->expectException(UnsupportedZipException::class);
        $this->expectExceptionMessageMatches('/65536 entries is more than the 65535/');

        $writer->build();
    }

    public function testExactlyAsManyEntriesAsTheFormatAllowsIsFine(): void
    {
        $writer = new ZipWriter();
        for ($i = 0; $i < 0xFFFF; ++$i) {
            $writer = $writer->addStored(\sprintf('f%d.txt', $i), 'x');
        }

        self::assertNotSame('', $writer->build());
    }

    /**
     * Declared rather than actual, so the guard can be checked without
     * allocating four gigabytes. In real use the two are the same thing.
     */
    public function testAnEntryTooLargeForTheFormatIsRefused(): void
    {
        $entry = new ZipEntry(
            'enormous.bin',
            ZipEntry::METHOD_STORE,
            0,
            0,
            self::UINT32_MAX + 1,
            self::UINT32_MAX + 1,
            0,
            0,
            'x',
        );

        $this->expectException(UnsupportedZipException::class);
        $this->expectExceptionMessageMatches('/needs ZIP64/');

        (new ZipWriter())->addEntry($entry)->build();
    }

    public function testAnEntryAtTheFormatsLimitIsAccepted(): void
    {
        $entry = new ZipEntry('big.bin', ZipEntry::METHOD_STORE, 0, 0, self::UINT32_MAX, self::UINT32_MAX, 0, 0, 'x');

        self::assertNotSame('', (new ZipWriter())->addEntry($entry)->build());
    }
}
