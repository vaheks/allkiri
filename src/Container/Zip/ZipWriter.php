<?php

declare(strict_types=1);

namespace Allkiri\Container\Zip;

use Allkiri\Exception\InvalidArgumentException;

/**
 * Writes a ZIP archive with full control over what ASiC-E cares about: entry
 * order, compression method, and the absence of extra fields on the mimetype
 * entry.
 *
 * Existing entries are re-emitted from their compressed bytes, so appending a
 * signature to a container never disturbs what was signed.
 */
final class ZipWriter
{
    /**
     * A fixed MS-DOS timestamp (1980-01-01 00:00:00), so that two runs over
     * the same input produce byte-identical archives. ASiC-E does not use the
     * timestamps, and reproducibility is worth more than a wall-clock date.
     */
    public const FIXED_DOS_DATE = 0x0021;
    public const FIXED_DOS_TIME = 0x0000;

    /** @var list<ZipEntry> */
    private array $entries = [];

    /**
     * Copy an entry from another archive, bytes and all.
     */
    public function addEntry(ZipEntry $entry): self
    {
        $this->entries[] = $entry;

        return $this;
    }

    public function addStored(string $name, string $content): self
    {
        return $this->addEntry(new ZipEntry(
            $name,
            ZipEntry::METHOD_STORE,
            0,
            crc32($content),
            \strlen($content),
            \strlen($content),
            self::FIXED_DOS_TIME,
            self::FIXED_DOS_DATE,
            $content,
        ));
    }

    public function addDeflated(string $name, string $content): self
    {
        $compressed = gzdeflate($content, 9);
        if ($compressed === false || \strlen($compressed) >= \strlen($content)) {
            return $this->addStored($name, $content);
        }

        return $this->addEntry(new ZipEntry(
            $name,
            ZipEntry::METHOD_DEFLATE,
            0,
            crc32($content),
            \strlen($compressed),
            \strlen($content),
            self::FIXED_DOS_TIME,
            self::FIXED_DOS_DATE,
            $compressed,
        ));
    }

    public function has(string $name): bool
    {
        foreach ($this->entries as $entry) {
            if ($entry->name === $name) {
                return true;
            }
        }

        return false;
    }

    public function build(): string
    {
        if ($this->entries === []) {
            throw new InvalidArgumentException('Cannot write an empty ZIP archive');
        }
        $local = '';
        $central = '';
        $offset = 0;
        foreach ($this->entries as $entry) {
            $name = $entry->name;
            $record = "PK\x03\x04"
                . pack('vvvvvVVVvv', $entry->versionNeeded, $entry->flags & ~0x08, $entry->method, $entry->dosTime, $entry->dosDate, $entry->crc32, $entry->compressedSize, $entry->uncompressedSize, \strlen($name), \strlen($entry->localExtra))
                . $name . $entry->localExtra . $entry->compressedData;
            $central .= "PK\x01\x02"
                . pack(
                    'vvvvvvVVVvvvvvVV',
                    $entry->versionMadeBy,
                    $entry->versionNeeded,
                    $entry->flags & ~0x08,
                    $entry->method,
                    $entry->dosTime,
                    $entry->dosDate,
                    $entry->crc32,
                    $entry->compressedSize,
                    $entry->uncompressedSize,
                    \strlen($name),
                    \strlen($entry->centralExtra),
                    \strlen($entry->comment),
                    0,
                    $entry->internalAttributes,
                    $entry->externalAttributes,
                    $offset,
                )
                . $name . $entry->centralExtra . $entry->comment;
            $offset += \strlen($record);
            $local .= $record;
        }

        return $local . $central . "PK\x05\x06" . pack('vvvvVVv', 0, 0, \count($this->entries), \count($this->entries), \strlen($central), \strlen($local), 0);
    }
}
