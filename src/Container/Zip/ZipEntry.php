<?php

declare(strict_types=1);

namespace Allkiri\Container\Zip;

/**
 * One entry of a ZIP archive, with the bytes exactly as they appear in the
 * file so an existing entry can be copied into a new archive untouched.
 */
final readonly class ZipEntry
{
    public const METHOD_STORE = 0;
    public const METHOD_DEFLATE = 8;

    public function __construct(
        public string $name,
        public int $method,
        public int $flags,
        public int $crc32,
        public int $compressedSize,
        public int $uncompressedSize,
        public int $dosTime,
        public int $dosDate,
        public string $compressedData,
        public string $localExtra = '',
        public string $centralExtra = '',
        public string $comment = '',
        public int $externalAttributes = 0,
        public int $internalAttributes = 0,
        public int $versionMadeBy = 0x0314,
        public int $versionNeeded = 20,
        /** Shared with the other entries of the same container; null means no limit. */
        public ?InflationLimit $limit = null,
    ) {}

    public function isStored(): bool
    {
        return $this->method === self::METHOD_STORE;
    }

    public function hasDataDescriptor(): bool
    {
        return ($this->flags & 0x08) !== 0;
    }

    public function isDirectory(): bool
    {
        return str_ends_with($this->name, '/');
    }

    /**
     * The entry's content, inflating it when necessary.
     */
    public function content(): string
    {
        if ($this->method === self::METHOD_STORE) {
            return $this->compressedData;
        }
        if ($this->method !== self::METHOD_DEFLATE) {
            throw new UnsupportedZipException(\sprintf('Entry "%s" uses unsupported compression method %d', $this->name, $this->method));
        }
        if ($this->limit !== null) {
            return $this->limit->inflate($this->name, $this->compressedData, $this->uncompressedSize);
        }

        $inflated = @gzinflate($this->compressedData);
        if ($inflated === false) {
            throw new UnsupportedZipException(\sprintf('Entry "%s" could not be decompressed', $this->name));
        }

        return $inflated;
    }
}
