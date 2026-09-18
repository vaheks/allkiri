<?php

declare(strict_types=1);

namespace Allkiri\Container;

use Allkiri\Xml\InvalidXmlException;
use Allkiri\Xml\Xml;

/**
 * META-INF/manifest.xml: the OASIS manifest an ASiC-E container carries,
 * listing the container itself and every data file with its media type.
 */
final readonly class Manifest
{
    /** The OpenDocument manifest namespace the file is written in. */
    public const NS_MANIFEST = 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0';

    /**
     * @param list<array{fullPath: string, mediaType: string}> $entries without the root entry
     */
    public function __construct(public array $entries) {}

    /**
     * @param list<DataFile> $dataFiles
     */
    public static function forDataFiles(array $dataFiles): self
    {
        $entries = [];
        foreach ($dataFiles as $file) {
            $entries[] = ['fullPath' => $file->name, 'mediaType' => $file->mimeType];
        }

        return new self($entries);
    }

    public static function parse(string $xml): self
    {
        try {
            $document = Xml::load($xml);
        } catch (InvalidXmlException $e) {
            throw new InvalidContainerException('META-INF/manifest.xml is not well-formed: ' . $e->getMessage(), 0, $e);
        }
        $root = $document->documentElement;
        if ($root === null || $root->localName !== 'manifest') {
            throw new InvalidContainerException('META-INF/manifest.xml has no manifest element');
        }
        $xpath = Xml::xpath($document, ['manifest' => self::NS_MANIFEST]);

        $entries = [];
        foreach (Xml::elements($xpath, 'manifest:file-entry', $root) as $entry) {
            $path = $entry->getAttributeNS(self::NS_MANIFEST, 'full-path');
            $type = $entry->getAttributeNS(self::NS_MANIFEST, 'media-type');
            if ($path === '' || $path === '/') {
                continue; // the root entry describes the container itself
            }
            $entries[] = ['fullPath' => $path, 'mediaType' => $type];
        }

        return new self($entries);
    }

    /**
     * The manifest exactly as digidoc4j and DigiDoc4 write it: one line, the
     * root entry first, then the data files in container order.
     */
    public function toXml(): string
    {
        $xml = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>'
            . '<manifest:manifest xmlns:manifest="' . self::NS_MANIFEST . '" manifest:version="1.2">'
            . '<manifest:file-entry manifest:full-path="/" manifest:media-type="' . AsicContainer::MIME_TYPE . '"/>';
        foreach ($this->entries as $entry) {
            $xml .= '<manifest:file-entry manifest:full-path="' . self::escape($entry['fullPath']) . '" manifest:media-type="' . self::escape($entry['mediaType']) . '"/>';
        }

        return $xml . '</manifest:manifest>';
    }

    public function mediaTypeOf(string $fullPath): ?string
    {
        foreach ($this->entries as $entry) {
            if ($entry['fullPath'] === $fullPath) {
                return $entry['mediaType'];
            }
        }

        return null;
    }

    /**
     * @return list<string>
     */
    public function paths(): array
    {
        return array_map(static fn(array $e): string => $e['fullPath'], $this->entries);
    }

    /**
     * @return list<string> every path listed more than once, each named once
     */
    public function duplicatePaths(): array
    {
        $seen = [];
        $duplicates = [];
        foreach ($this->paths() as $path) {
            if (isset($seen[$path]) && !\in_array($path, $duplicates, true)) {
                $duplicates[] = $path;
            }
            $seen[$path] = true;
        }

        return $duplicates;
    }

    /**
     * A value as an XML attribute.
     *
     * Refuses what cannot be written rather than writing something else.
     * `htmlspecialchars` with explicit flags returns the empty string for input
     * that is not valid UTF-8, so a data file whose name is not UTF-8 used to
     * become `full-path=""`: the manifest went into the container, the
     * signature covered it, and reading it back said the file was not listed.
     * A name that cannot be represented is a reason to stop, not to guess.
     *
     * ENT_SUBSTITUTE stands behind the check, so no path here can return the
     * empty string for a value that is not empty.
     */
    private static function escape(string $value): string
    {
        if (!mb_check_encoding($value, 'UTF-8')) {
            throw new ContainerException(\sprintf(
                'The manifest cannot hold "%s": it is not valid UTF-8, and the manifest is a UTF-8 document',
                addcslashes($value, "\0..\37\\\""),
            ));
        }

        return htmlspecialchars($value, ENT_QUOTES | ENT_XML1 | ENT_SUBSTITUTE, 'UTF-8');
    }
}
