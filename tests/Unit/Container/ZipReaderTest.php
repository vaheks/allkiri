<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Container;

use Allkiri\Container\AsicReader;
use Allkiri\Container\InvalidContainerException;
use Allkiri\Container\Zip\ZipEntry;
use Allkiri\Container\Zip\ZipWriter;
use Allkiri\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * An archive that two readers could read differently is refused rather than
 * read one way, and so is one that disagrees with itself about its content.
 */
#[CoversNothing]
final class ZipReaderTest extends TestCase
{
    /**
     * Pairs of names of equal length, so one can be written over the other.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function namePairs(): iterable
    {
        yield 'a data file' => ['leping.pdf', 'leping.pdX'];
        yield 'a signature file' => ['META-INF/signatures0.xml', 'META-INF/signatures9.xml'];
        yield 'the mimetype' => ['mimetype', 'mimetypX'];
    }

    #[DataProvider('namePairs')]
    public function testTwoEntriesWithOneNameAreRefused(string $name, string $other): void
    {
        // The writer will not make such an archive, so make a sound one and
        // give the second entry the first one's name in both of its headers.
        $sound = (new ZipWriter())
            ->addStored($name, 'the document that was checked')
            ->addStored($other, 'a document shown instead')
            ->build();
        $duplicated = str_replace($other, $name, $sound);
        self::assertSame(4, substr_count($duplicated, $name), 'both entries, both headers');

        $this->expectException(InvalidContainerException::class);
        $this->expectExceptionMessage(\sprintf('more than one entry named "%s"', $name));

        (new AsicReader())->read($duplicated);
    }

    public function testAnEntryNamedDifferentlyInItsLocalHeaderIsRefused(): void
    {
        $sound = (new ZipWriter())->addStored('leping.pdf', 'content')->build();
        // The local header comes first in the file, the central directory last.
        $position = strpos($sound, 'leping.pdf');
        self::assertIsInt($position);
        $mismatched = substr_replace($sound, 'lepinq.pdf', $position, \strlen('leping.pdf'));

        $this->expectException(InvalidContainerException::class);
        $this->expectExceptionMessage('Entry "leping.pdf" is named "lepinq.pdf" in its local header');

        (new AsicReader())->read($mismatched);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function methods(): iterable
    {
        yield 'stored' => [ZipEntry::METHOD_STORE];
        yield 'deflated' => [ZipEntry::METHOD_DEFLATE];
    }

    #[DataProvider('methods')]
    public function testContentThatDoesNotMatchItsCrcIsRefused(int $method): void
    {
        $content = str_repeat('Tere, allkiri! ', 20);
        $data = $method === ZipEntry::METHOD_STORE ? $content : (string) gzdeflate($content, 9);
        $archive = static fn(int $crc): string => (new ZipWriter())
            ->addEntry(new ZipEntry('leping.txt', $method, 0, $crc, \strlen($data), \strlen($content), 0, 0x21, $data))
            ->build();

        self::assertSame($content, (new AsicReader())->read($archive(crc32($content)))->dataFiles[0]->content, 'the right CRC reads');

        $this->expectException(InvalidContainerException::class);
        $this->expectExceptionMessage('Entry "leping.txt" is corrupt');

        (new AsicReader())->read($archive(crc32($content) ^ 1));
    }

    public function testTheWriterWillNotMakeTwoEntriesWithOneName(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('already holds an entry named "leping.pdf"');

        (new ZipWriter())->addStored('leping.pdf', 'one')->addStored('leping.pdf', 'two')->build();
    }
}
