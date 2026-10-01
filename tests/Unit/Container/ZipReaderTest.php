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

    /**
     * A streaming reader walks the local headers and never sees the central
     * directory. Each of these makes it read the entry differently.
     *
     * @return iterable<string, array{int, string, string}>
     */
    public static function localHeaderDisagreements(): iterable
    {
        // Offsets into the first local header: flags at 6, method at 8, CRC-32
        // at 14, sizes at 18 and 22.
        yield 'deflated, says the local header' => [8, pack('v', ZipEntry::METHOD_DEFLATE), 'a different compression method in its local header'];
        yield 'encrypted, says the local header' => [6, pack('v', 0x01), 'different flags in its local header'];
        yield 'another CRC-32' => [14, pack('V', 0x12345678), 'a different CRC-32 in its local header'];
        yield 'a shorter entry' => [18, pack('V', 3), 'a different compressed size in its local header'];
        yield 'a longer entry' => [22, pack('V', 999), 'a different size in its local header'];
    }

    #[DataProvider('localHeaderDisagreements')]
    public function testALocalHeaderThatDisagreesWithTheDirectoryIsRefused(int $offset, string $bytes, string $message): void
    {
        $sound = (new ZipWriter())->addStored('leping.txt', 'the document that was checked')->build();
        self::assertSame('leping.txt', (new AsicReader())->read($sound)->dataFiles[0]->name);

        $this->expectException(InvalidContainerException::class);
        $this->expectExceptionMessage('Entry "leping.txt" has ' . $message);

        (new AsicReader())->read(substr_replace($sound, $bytes, $offset, \strlen($bytes)));
    }

    /**
     * Java's writer, which digidoc4j uses, leaves the local header's CRC and
     * sizes at zero and writes them in a descriptor after the data. Every
     * container from digidoc4j is shaped so; the descriptor must agree too.
     */
    public function testADataDescriptorThatDisagreesWithTheDirectoryIsRefused(): void
    {
        $container = (string) file_get_contents(__DIR__ . '/../../fixtures/containers/valid-asice.asice');
        self::assertCount(1, (new AsicReader())->read($container)->dataFiles, 'the shape reads');
        $descriptor = strpos($container, "PK\x07\x08");
        self::assertIsInt($descriptor);

        $this->expectException(InvalidContainerException::class);
        $this->expectExceptionMessageMatches('/has a different CRC-32 in its data descriptor/');

        (new AsicReader())->read(substr_replace($container, pack('V', 0x12345678), $descriptor + 4, 4));
    }

    public function testEntriesThatShareBytesAreRefused(): void
    {
        // The second entry's local record, carried inside the first entry's data.
        $inner = (new ZipWriter())->addStored('second.txt', 'shown by one reader')->build();
        $innerRecord = substr($inner, 0, (int) strpos($inner, "PK\x01\x02"));
        $archive = (new ZipWriter())->addStored('first.txt', $innerRecord)->addStored('second.txt', 'shown by one reader')->build();
        // Point the directory's second entry at the copy inside the first.
        $copyAt = strpos($archive, $innerRecord);
        $secondCentral = strrpos($archive, "PK\x01\x02");
        self::assertIsInt($copyAt);
        self::assertIsInt($secondCentral);

        $this->expectException(InvalidContainerException::class);
        $this->expectExceptionMessage('Entries "first.txt" and "second.txt" share bytes');

        (new AsicReader())->read(substr_replace($archive, pack('V', $copyAt), $secondCentral + 42, 4));
    }

    /**
     * @return iterable<string, array{\Closure(string): string, string}>
     */
    public static function endRecordDisagreements(): iterable
    {
        yield 'bytes after the end record' => [static fn(string $zip): string => $zip . 'trailing', 'does not end the archive'];
        yield 'an end record planted in the comment' => [
            // The real record now claims a comment that holds a second record,
            // which a reader searching from the end finds first. That one is
            // last in the file, but the directory does not end where it sits.
            static fn(string $zip): string => substr_replace($zip, pack('v', 22), -2) . substr($zip, -22),
            'does not end where',
        ];
        // The one entry's directory record is 46 bytes and its name.
        yield 'a directory larger than it is' => [static fn(string $zip): string => substr_replace($zip, pack('V', 46 + \strlen('leping.txt') + 1), -10, 4), 'does not end where'];
        yield 'two counts of the entries' => [static fn(string $zip): string => substr_replace($zip, pack('v', 2), -14, 2), 'counts the entries two ways'];
    }

    /**
     * @param \Closure(string): string $damage
     */
    #[DataProvider('endRecordDisagreements')]
    public function testAnEndRecordThatDoesNotDescribeTheArchiveIsRefused(\Closure $damage, string $message): void
    {
        $sound = (new ZipWriter())->addStored('leping.txt', 'content')->build();

        $this->expectException(InvalidContainerException::class);
        $this->expectExceptionMessage($message);

        (new AsicReader())->read($damage($sound));
    }

    public function testTheWriterWillNotMakeTwoEntriesWithOneName(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('already holds an entry named "leping.pdf"');

        (new ZipWriter())->addStored('leping.pdf', 'one')->addStored('leping.pdf', 'two')->build();
    }
}
