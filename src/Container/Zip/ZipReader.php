<?php

declare(strict_types=1);

namespace Allkiri\Container\Zip;

use Allkiri\Container\InvalidContainerException;

/**
 * Reads a ZIP archive through its central directory, keeping the compressed
 * bytes of every entry so they can be re-emitted without re-compression.
 *
 * ext-zip would read the contents but not answer the questions an ASiC-E
 * validator must ask: which entry comes first, whether it is stored, whether
 * it carries extra fields.
 */
final class ZipReader
{
    private const SIGNATURE_EOCD = "PK\x05\x06";
    private const SIGNATURE_CENTRAL = "PK\x01\x02";
    private const SIGNATURE_LOCAL = "PK\x03\x04";
    private const SIGNATURE_ZIP64_LOCATOR = "PK\x06\x07";
    private const MAX_COMMENT_LENGTH = 0xFFFF;
    private const UINT32_MAX = 0xFFFFFFFF;

    private function __construct() {}

    /**
     *
     * @throws InvalidContainerException
     * @return list<ZipEntry> in central-directory order, which is the order the entries were written
     */
    public static function read(string $bytes): array
    {
        $eocdOffset = self::findEndOfCentralDirectory($bytes);
        if (str_contains(substr($bytes, max(0, $eocdOffset - 20), 20), self::SIGNATURE_ZIP64_LOCATOR)) {
            throw new UnsupportedZipException('ZIP64 archives are not supported');
        }
        $eocd = new Fields('vdiskNumber/vcentralDisk/vcountOnDisk/vcount/VcentralSize/VcentralOffset/vcommentLength', substr($bytes, $eocdOffset + 4, 18), 'end of central directory');
        if ($eocd->get('diskNumber') !== 0 || $eocd->get('centralDisk') !== 0) {
            throw new UnsupportedZipException('Multi-disk archives are not supported');
        }
        if ($eocd->get('count') === 0xFFFF || $eocd->get('centralOffset') === self::UINT32_MAX) {
            throw new UnsupportedZipException('ZIP64 archives are not supported');
        }

        $entries = [];
        $offset = $eocd->get('centralOffset');
        for ($i = 0; $i < $eocd->get('count'); ++$i) {
            if (substr($bytes, $offset, 4) !== self::SIGNATURE_CENTRAL) {
                throw new InvalidContainerException(\sprintf('Central directory entry %d is malformed', $i));
            }
            $central = new Fields(
                'vversionMadeBy/vversionNeeded/vflags/vmethod/vtime/vdate/Vcrc32/VcompressedSize/VuncompressedSize/vnameLength/vextraLength/vcommentLength/vdiskStart/vinternalAttributes/VexternalAttributes/VlocalOffset',
                substr($bytes, $offset + 4, 42),
                \sprintf('central directory entry %d', $i),
            );
            $nameLength = $central->get('nameLength');
            $extraLength = $central->get('extraLength');
            $commentLength = $central->get('commentLength');
            $name = substr($bytes, $offset + 46, $nameLength);
            $centralExtra = substr($bytes, $offset + 46 + $nameLength, $extraLength);
            $comment = substr($bytes, $offset + 46 + $nameLength + $extraLength, $commentLength);
            $offset += 46 + $nameLength + $extraLength + $commentLength;

            if (($central->get('flags') & 0x01) !== 0) {
                throw new UnsupportedZipException(\sprintf('Entry "%s" is encrypted', $name));
            }
            if ($central->get('compressedSize') === self::UINT32_MAX || $central->get('uncompressedSize') === self::UINT32_MAX || $central->get('localOffset') === self::UINT32_MAX) {
                throw new UnsupportedZipException(\sprintf('Entry "%s" needs ZIP64', $name));
            }

            $entries[] = self::readLocal($bytes, $central, $name, $centralExtra, $comment);
        }

        return $entries;
    }

    private static function readLocal(string $bytes, Fields $central, string $name, string $centralExtra, string $comment): ZipEntry
    {
        $offset = $central->get('localOffset');
        if (substr($bytes, $offset, 4) !== self::SIGNATURE_LOCAL) {
            throw new InvalidContainerException(\sprintf('Entry "%s" has no local header', $name));
        }
        $local = new Fields(
            'vversionNeeded/vflags/vmethod/vtime/vdate/Vcrc32/VcompressedSize/VuncompressedSize/vnameLength/vextraLength',
            substr($bytes, $offset + 4, 26),
            \sprintf('local header of "%s"', $name),
        );
        $compressedSize = $central->get('compressedSize');
        $dataOffset = $offset + 30 + $local->get('nameLength') + $local->get('extraLength');
        $data = substr($bytes, $dataOffset, $compressedSize);
        if (\strlen($data) !== $compressedSize) {
            throw new InvalidContainerException(\sprintf('Entry "%s" is truncated', $name));
        }

        return new ZipEntry(
            $name,
            $central->get('method'),
            $central->get('flags'),
            $central->get('crc32'),
            $compressedSize,
            $central->get('uncompressedSize'),
            $central->get('time'),
            $central->get('date'),
            $data,
            substr($bytes, $offset + 30 + $local->get('nameLength'), $local->get('extraLength')),
            $centralExtra,
            $comment,
            $central->get('externalAttributes'),
            $central->get('internalAttributes'),
            $central->get('versionMadeBy'),
            $central->get('versionNeeded'),
        );
    }

    private static function findEndOfCentralDirectory(string $bytes): int
    {
        if (\strlen($bytes) < 22) {
            throw new InvalidContainerException('Not a ZIP archive: too short');
        }
        // The record sits within the last 22 bytes plus the archive comment,
        // so only that tail is searched, from its end backwards.
        $tailStart = max(0, \strlen($bytes) - 22 - self::MAX_COMMENT_LENGTH);
        $position = strrpos(substr($bytes, $tailStart), self::SIGNATURE_EOCD);
        if ($position === false) {
            throw new InvalidContainerException('Not a ZIP archive: no end of central directory');
        }

        return $tailStart + $position;
    }
}
