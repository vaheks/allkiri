<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Container;

use Allkiri\Container\AsicContainer;
use Allkiri\Container\AsicReader;
use Allkiri\Container\AsicWriter;
use Allkiri\Container\ContainerException;
use Allkiri\Container\DataFile;
use Allkiri\Container\InvalidContainerException;
use Allkiri\Container\Manifest;
use Allkiri\Container\MimeTypes;
use Allkiri\Container\SignatureFile;
use Allkiri\Container\StructuralFinding;
use Allkiri\Container\UnsupportedZipException;
use Allkiri\Container\Zip\ZipEntry;
use Allkiri\Container\Zip\ZipReader;
use Allkiri\Container\Zip\ZipWriter;
use Allkiri\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class AsicContainerTest extends TestCase
{
    private const CONTAINERS = __DIR__ . '/../../fixtures/containers/';

    public function testANewContainerHasTheByteLayoutAsicERequires(): void
    {
        $container = AsicContainer::create(
            DataFile::fromString('hello.txt', "Tere, allkiri!\n"),
            DataFile::fromString('data.csv', str_repeat("a,b,c\n", 500)),
        );
        $bytes = (new AsicWriter())->write($container);
        $entries = ZipReader::read($bytes);

        self::assertSame(['mimetype', 'hello.txt', 'data.csv', 'META-INF/manifest.xml'], array_map(static fn(ZipEntry $e): string => $e->name, $entries));
        self::assertSame(0, strpos($bytes, "PK\x03\x04"), 'the archive starts with the first local header');
        self::assertSame('mimetype', $entries[0]->name);
        self::assertTrue($entries[0]->isStored(), 'mimetype must not be compressed');
        self::assertSame('', $entries[0]->localExtra, 'mimetype must carry no extra field');
        self::assertSame('', $entries[0]->centralExtra);
        self::assertFalse($entries[0]->hasDataDescriptor());
        self::assertSame(AsicContainer::MIME_TYPE, $entries[0]->content());
        // The mimetype content must sit at a fixed offset so a reader can find it without parsing.
        self::assertSame(AsicContainer::MIME_TYPE, substr($bytes, 38, \strlen(AsicContainer::MIME_TYPE)));

        self::assertSame(ZipEntry::METHOD_DEFLATE, $entries[2]->method, 'repetitive data compresses');
        self::assertSame("Tere, allkiri!\n", $entries[1]->content());

        // ext-zip must agree with our own writer.
        $path = tempnam(sys_get_temp_dir(), 'allkiri') . '.asice';
        file_put_contents($path, $bytes);
        $zip = new \ZipArchive();
        self::assertTrue($zip->open($path) === true);
        self::assertSame(4, $zip->numFiles);
        self::assertSame("Tere, allkiri!\n", $zip->getFromName('hello.txt'));
        self::assertSame(AsicContainer::MIME_TYPE, $zip->getFromName('mimetype'));
        $zip->close();
        unlink($path);
    }

    public function testWritingIsReproducible(): void
    {
        $container = AsicContainer::create(DataFile::fromString('a.txt', 'content'));
        $writer = new AsicWriter();

        self::assertSame($writer->write($container), $writer->write($container));
    }

    public function testReadingADigidoc4jContainer(): void
    {
        $container = (new AsicReader())->readFile(self::CONTAINERS . 'valid-asice-esteid2018.asice');

        self::assertSame([], $container->structuralFindings);
        self::assertCount(1, $container->dataFiles);
        self::assertSame('test.txt', $container->dataFiles[0]->name);
        self::assertSame('text/plain', $container->dataFiles[0]->mimeType, 'the media type comes from the manifest');
        self::assertCount(1, $container->signatureFiles);
        self::assertSame('META-INF/signatures0.xml', $container->signatureFiles[0]->name);
        self::assertStringContainsString('XAdESSignatures', $container->signatureFiles[0]->xml);
        self::assertSame('META-INF/signatures1.xml', $container->nextSignatureFileName());
        self::assertFalse($container->isNew());
        self::assertNotNull($container->dataFile('test.txt'));
        self::assertNull($container->dataFile('missing.txt'));

        // A container whose signatures file is signatures1.xml still gets a fresh index.
        $lta = (new AsicReader())->readFile(self::CONTAINERS . 'valid-asice-lta.asice');
        self::assertSame('META-INF/signatures1.xml', $lta->signatureFiles[0]->name);
        self::assertSame('META-INF/signatures2.xml', $lta->nextSignatureFileName());

        $two = (new AsicReader())->readFile(self::CONTAINERS . '2_signatures_duplicate_id.asice');
        self::assertCount(2, $two->signatureFiles);
        self::assertSame('META-INF/signatures2.xml', $two->nextSignatureFileName());
    }

    public function testAppendingASignaturePreservesEveryOriginalByte(): void
    {
        $original = (string) file_get_contents(self::CONTAINERS . 'valid-asice-esteid2018.asice');
        $container = (new AsicReader())->read($original);

        $appended = $container->withSignatureFile(new SignatureFile('META-INF/signatures1.xml', '<x xmlns="urn:test"/>'));
        $bytes = (new AsicWriter())->write($appended);

        $before = ZipReader::read($original);
        $after = ZipReader::read($bytes);
        self::assertCount(\count($before) + 1, $after);
        foreach ($before as $i => $entry) {
            self::assertSame($entry->name, $after[$i]->name);
            self::assertSame($entry->method, $after[$i]->method);
            self::assertSame($entry->crc32, $after[$i]->crc32);
            self::assertSame($entry->compressedData, $after[$i]->compressedData, $entry->name . ' compressed bytes');
            self::assertSame($entry->localExtra, $after[$i]->localExtra);
        }
        self::assertSame('META-INF/signatures1.xml', $after[\count($after) - 1]->name);

        // The re-read container still has both signatures and the untouched data file.
        $reread = (new AsicReader())->read($bytes);
        self::assertCount(2, $reread->signatureFiles);
        self::assertSame($container->dataFiles[0]->content, $reread->dataFiles[0]->content);
        self::assertSame($container->fingerprint(), $reread->fingerprint());
        self::assertSame([], $reread->structuralFindings);
    }

    public function testStructuralProblemsAreReportedNotThrown(): void
    {
        // mimetype second and compressed, and a data file the manifest does not mention.
        $deflated = (string) gzdeflate(AsicContainer::MIME_TYPE, 9);
        $zip = (new ZipWriter())
            ->addDeflated('data.txt', 'x')
            ->addEntry(new ZipEntry('mimetype', ZipEntry::METHOD_DEFLATE, 0, crc32(AsicContainer::MIME_TYPE), \strlen($deflated), \strlen(AsicContainer::MIME_TYPE), 0, 0x21, $deflated))
            ->addDeflated('META-INF/manifest.xml', (new Manifest([['fullPath' => 'ghost.txt', 'mediaType' => 'text/plain']]))->toXml())
            ->addDeflated('META-INF/rubbish.txt', 'stray');
        $container = (new AsicReader())->read($zip->build());

        $codes = array_map(static fn(StructuralFinding $f): string => $f->code, $container->structuralFindings);
        self::assertContains(StructuralFinding::MIMETYPE_NOT_FIRST, $codes);
        self::assertContains(StructuralFinding::MIMETYPE_COMPRESSED, $codes);
        self::assertContains(StructuralFinding::FILE_MISSING_MANIFEST_ENTRY, $codes);
        self::assertContains(StructuralFinding::MANIFEST_ENTRY_MISSING_FILE, $codes);
        self::assertContains(StructuralFinding::UNEXPECTED_META_INF_ENTRY, $codes);
        self::assertContains(StructuralFinding::NO_SIGNATURE_FILES, $codes);
        self::assertNotContains(StructuralFinding::UNEXPECTED_META_INF_ENTRY, array_map(static fn(StructuralFinding $f): string => $f->code, $container->fatalFindings()));

        $empty = (new AsicReader())->read((new ZipWriter())->addStored('mimetype', AsicContainer::MIME_TYPE)->build());
        $emptyCodes = array_map(static fn(StructuralFinding $f): string => $f->code, $empty->structuralFindings);
        self::assertContains(StructuralFinding::MANIFEST_MISSING, $emptyCodes);
        self::assertContains(StructuralFinding::NO_DATA_FILES, $emptyCodes);
    }

    public function testAManifestListingAFileTwiceIsAFatalFinding(): void
    {
        $manifest = new Manifest([
            ['fullPath' => 'a.txt', 'mediaType' => 'text/plain'],
            ['fullPath' => 'a.txt', 'mediaType' => 'application/pdf'],
            ['fullPath' => 'a.txt', 'mediaType' => 'text/html'],
        ]);
        $bytes = (new ZipWriter())
            ->addStored('mimetype', AsicContainer::MIME_TYPE)
            ->addDeflated('a.txt', 'x')
            ->addDeflated('META-INF/manifest.xml', $manifest->toXml())
            ->build();

        $duplicates = array_values(array_filter(
            (new AsicReader())->read($bytes)->fatalFindings(),
            static fn(StructuralFinding $f): bool => $f->code === StructuralFinding::MANIFEST_DUPLICATE_ENTRY,
        ));

        self::assertCount(1, $duplicates, 'one finding per path, however often it is repeated');
        self::assertStringContainsString('"a.txt"', $duplicates[0]->message);
    }

    public function testNonZipAndUnsupportedZipsAreRejected(): void
    {
        try {
            (new AsicReader())->read('this is not a zip file at all');
            self::fail('arbitrary bytes accepted');
        } catch (InvalidContainerException $e) {
            self::assertStringContainsString('ZIP', $e->getMessage());
        }

        // An entry whose compression method allkiri does not implement.
        $zip = (new ZipWriter())->addEntry(new ZipEntry('x.txt', 12, 0, crc32('x'), 1, 1, 0, 0x21, 'x'));
        $this->expectException(UnsupportedZipException::class);
        (new AsicReader())->read($zip->build())->dataFiles[0]->content;
    }

    public function testTheManifestMatchesWhatDigidoc4jWrites(): void
    {
        $xml = (new Manifest([['fullPath' => 'test.txt', 'mediaType' => 'text/plain']]))->toXml();

        self::assertSame(
            '<?xml version="1.0" encoding="UTF-8" standalone="no"?>'
            . '<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">'
            . '<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.etsi.asic-e+zip"/>'
            . '<manifest:file-entry manifest:full-path="test.txt" manifest:media-type="text/plain"/>'
            . '</manifest:manifest>',
            $xml,
        );

        $roundTripped = Manifest::parse($xml);
        self::assertSame(['test.txt'], $roundTripped->paths());
        self::assertSame('text/plain', $roundTripped->mediaTypeOf('test.txt'));
        self::assertNull($roundTripped->mediaTypeOf('/'));

        // The real manifest of a digidoc4j container parses to the same thing.
        $zip = new \ZipArchive();
        $zip->open(self::CONTAINERS . 'valid-asice-esteid2018.asice');
        $real = Manifest::parse((string) $zip->getFromName('META-INF/manifest.xml'));
        $zip->close();
        self::assertSame(['test.txt'], $real->paths());
        self::assertSame('text/plain', $real->mediaTypeOf('test.txt'));

        // Names needing escaping survive a round trip.
        $odd = new Manifest([['fullPath' => 'a & "b".txt', 'mediaType' => 'text/plain']]);
        self::assertSame(['a & "b".txt'], Manifest::parse($odd->toXml())->paths());
    }

    public function testAManifestThatIsNotXmlIsRefusedAsAContainerFailure(): void
    {
        $this->expectException(InvalidContainerException::class);
        $this->expectExceptionMessage('META-INF/manifest.xml is not well-formed');

        Manifest::parse('<manifest:manifest');
    }

    public function testDataFileNamesAreGuardedAndMediaTypesGuessed(): void
    {
        self::assertSame('text/plain', MimeTypes::guess('a.TXT'));
        self::assertSame('application/pdf', MimeTypes::guess('contract.pdf'));
        self::assertSame('application/vnd.etsi.asic-e+zip', MimeTypes::guess('nested.asice'));
        self::assertSame(MimeTypes::DEFAULT, MimeTypes::guess('no-extension'));
        self::assertSame(MimeTypes::DEFAULT, MimeTypes::guess('archive.unknown'));

        $refused = [
            '',
            'META-INF/signatures0.xml',
            'mimetype',
            '/absolute.txt',
            '../escape.txt',
            'a/../../b.txt',
            'back\\slash.txt',
            // A control character makes a name that reads as another one.
            "trailing-newline.txt\n",
            "carriage\r.txt",
            "tab\there.txt",
            "delete\x7F.txt",
        ];
        foreach ($refused as $name) {
            try {
                new DataFile($name, 'x');
                self::fail(\sprintf('"%s" was accepted as a data file name', addcslashes($name, "\0..\37")));
            } catch (InvalidArgumentException) {
            }
        }
        self::assertSame('sub/dir/file.txt', (new DataFile('sub/dir/file.txt', 'x'))->name, 'subdirectories are allowed');
    }

    /**
     * PHP's $ matches before a trailing newline, so a pattern anchored with it
     * reads "META-INF/signatures.xml\n" as a signature file. libdigidocpp and
     * digidoc4j do not, and a container one validator reads as signed and
     * another as unsigned is exactly what the reader refuses elsewhere.
     */
    public function testAnEntryNamedLikeASignatureFileWithATrailingNewlineIsRefused(): void
    {
        try {
            new SignatureFile("META-INF/signatures.xml\n", '<x/>');
            self::fail('a signature file name with a trailing newline was accepted');
        } catch (InvalidArgumentException) {
        }

        self::assertNull((new SignatureFile('META-INF/signatures.xml', '<x/>'))->index());
        self::assertSame(7, (new SignatureFile('META-INF/signatures7.xml', '<x/>'))->index());
    }

    /**
     * A name that is not UTF-8 used to be escaped into the empty string, so the
     * manifest said nothing about the file while the signature covered it.
     */
    public function testAManifestRefusesANameItCannotRepresent(): void
    {
        $manifest = new Manifest([['fullPath' => "caf\xE9.txt", 'mediaType' => 'text/plain']]);

        $this->expectException(ContainerException::class);
        $this->expectExceptionMessage('not valid UTF-8');

        $manifest->toXml();
    }

    public function testContainerInvariants(): void
    {
        $file = DataFile::fromString('a.txt', 'x');

        try {
            AsicContainer::create();
            self::fail('a container with no data files was created');
        } catch (InvalidArgumentException) {
        }
        try {
            AsicContainer::create($file, DataFile::fromString('a.txt', 'y'));
            self::fail('duplicate data file names accepted');
        } catch (InvalidArgumentException) {
        }

        $container = AsicContainer::create($file)->withSignatureFile(new SignatureFile('META-INF/signatures0.xml', '<x/>'));
        try {
            $container->withSignatureFile(new SignatureFile('META-INF/signatures0.xml', '<y/>'));
            self::fail('a duplicate signature file name was accepted');
        } catch (InvalidArgumentException) {
        }

        $this->expectException(InvalidArgumentException::class);
        new SignatureFile('META-INF/notasignature.xml', '<x/>');
    }

    public function testFingerprintTracksTheSignedContentOnly(): void
    {
        $a = AsicContainer::create(DataFile::fromString('a.txt', 'x'), DataFile::fromString('b.txt', 'y'));
        $sameFilesOtherOrder = AsicContainer::create(DataFile::fromString('b.txt', 'y'), DataFile::fromString('a.txt', 'x'));
        $differentContent = AsicContainer::create(DataFile::fromString('a.txt', 'x'), DataFile::fromString('b.txt', 'z'));
        $differentType = AsicContainer::create(DataFile::fromString('a.txt', 'x'), new DataFile('b.txt', 'y', 'application/json'));

        self::assertSame($a->fingerprint(), $sameFilesOtherOrder->fingerprint());
        self::assertNotSame($a->fingerprint(), $differentContent->fingerprint());
        self::assertNotSame($a->fingerprint(), $differentType->fingerprint());
        self::assertSame($a->fingerprint(), $a->withSignatureFile(new SignatureFile('META-INF/signatures0.xml', '<x/>'))->fingerprint(), 'signing does not change what was signed');
    }
}
