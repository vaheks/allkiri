<?php

declare(strict_types=1);

namespace Allkiri\Container;

use Allkiri\Container\Zip\InflationLimit;
use Allkiri\Container\Zip\ZipEntry;
use Allkiri\Container\Zip\ZipReader;
use Allkiri\Xades\Ns;

/**
 * Reads an ASiC-E container.
 *
 * Structural problems become findings rather than exceptions: a validator
 * has to explain why a container is unacceptable, which it cannot do if
 * reading it throws. Only bytes that are not a readable ZIP at all throw.
 */
final class AsicReader
{
    public const MIMETYPE_ENTRY = 'mimetype';
    public const MANIFEST_ENTRY = 'META-INF/manifest.xml';

    /**
     * @param int $compressionRatioThresholdBytes expansion below this is never questioned
     * @param int $maxCompressionRatio            beyond it, the total may not exceed the
     *                                            container's own size times this
     */
    public function __construct(
        private readonly int $compressionRatioThresholdBytes = InflationLimit::DEFAULT_THRESHOLD_BYTES,
        private readonly int $maxCompressionRatio = InflationLimit::DEFAULT_MAX_RATIO,
    ) {}

    /**
     * @throws InvalidContainerException when the bytes are not a readable ZIP
     * @throws \Allkiri\Container\Zip\ZipBombException when it would expand out of
     *                                                all proportion to its size
     */
    public function read(string $bytes): AsicContainer
    {
        $entries = ZipReader::read($bytes, new InflationLimit(
            \strlen($bytes),
            $this->compressionRatioThresholdBytes,
            $this->maxCompressionRatio,
        ));
        $findings = [];

        $this->checkMimetype($entries, $findings);

        $manifest = null;
        $signatureFiles = [];
        $contents = [];
        foreach ($entries as $entry) {
            if ($entry->isDirectory()) {
                continue;
            }
            $name = $entry->name;
            if ($name === self::MIMETYPE_ENTRY) {
                continue;
            }
            if ($name === self::MANIFEST_ENTRY) {
                $manifest = Manifest::parse($entry->content());
                continue;
            }
            if (preg_match('#^META-INF/signatures\d*\.xml$#', $name) === 1) {
                $signatureFiles[] = new SignatureFile($name, $entry->content());
                continue;
            }
            if (str_starts_with($name, 'META-INF/')) {
                $findings[] = new StructuralFinding(StructuralFinding::UNEXPECTED_META_INF_ENTRY, \sprintf('"%s" is not part of the ASiC-E format', $name), false);
                continue;
            }
            $contents[$name] = $entry->content();
        }

        if ($manifest === null) {
            $findings[] = new StructuralFinding(StructuralFinding::MANIFEST_MISSING, 'The container has no META-INF/manifest.xml');
            $manifest = new Manifest([]);
        }

        $dataFiles = [];
        foreach ($contents as $name => $content) {
            $mediaType = $manifest->mediaTypeOf($name);
            if ($mediaType === null) {
                $findings[] = new StructuralFinding(StructuralFinding::FILE_MISSING_MANIFEST_ENTRY, \sprintf('"%s" is in the container but not in the manifest', $name));
            }
            $dataFiles[] = new DataFile($name, $content, $mediaType ?? MimeTypes::guess($name));
        }
        foreach ($manifest->paths() as $path) {
            if (!isset($contents[$path])) {
                $findings[] = new StructuralFinding(StructuralFinding::MANIFEST_ENTRY_MISSING_FILE, \sprintf('The manifest lists "%s", which the container does not contain', $path));
            }
        }
        if ($dataFiles === []) {
            $findings[] = new StructuralFinding(StructuralFinding::NO_DATA_FILES, 'The container has no data files');
        }
        if ($signatureFiles === []) {
            $findings[] = new StructuralFinding(StructuralFinding::NO_SIGNATURE_FILES, 'The container has no signature files');
        }

        return AsicContainer::fromParts($dataFiles, $signatureFiles, $manifest, $entries, $findings);
    }

    /**
     * @throws InvalidContainerException
     */
    public function readFile(string $path): AsicContainer
    {
        $bytes = @file_get_contents($path);
        if ($bytes === false) {
            throw new InvalidContainerException(\sprintf('Could not read "%s"', $path));
        }

        return $this->read($bytes);
    }

    /**
     * @param list<ZipEntry>          $entries
     * @param list<StructuralFinding> $findings
     */
    private function checkMimetype(array $entries, array &$findings): void
    {
        $index = null;
        foreach ($entries as $position => $entry) {
            if ($entry->name === self::MIMETYPE_ENTRY) {
                $index = $position;
                break;
            }
        }
        if ($index === null) {
            $findings[] = new StructuralFinding(StructuralFinding::MIMETYPE_MISSING, 'The container has no mimetype entry');

            return;
        }
        $entry = $entries[$index];
        if ($index !== 0) {
            $findings[] = new StructuralFinding(StructuralFinding::MIMETYPE_NOT_FIRST, 'The mimetype entry is not the first entry of the container');
        }
        if (!$entry->isStored()) {
            $findings[] = new StructuralFinding(StructuralFinding::MIMETYPE_COMPRESSED, 'The mimetype entry is compressed');
        }
        if ($entry->localExtra !== '' || $entry->centralExtra !== '') {
            $findings[] = new StructuralFinding(StructuralFinding::MIMETYPE_HAS_EXTRA_FIELD, 'The mimetype entry carries an extra field');
        }
        if (trim($entry->content()) !== Ns::MIME_ASICE) {
            $findings[] = new StructuralFinding(StructuralFinding::MIMETYPE_WRONG_CONTENT, \sprintf('The mimetype entry says "%s" instead of "%s"', trim($entry->content()), Ns::MIME_ASICE));
        }
    }
}
