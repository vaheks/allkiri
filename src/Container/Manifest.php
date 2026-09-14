<?php

declare(strict_types=1);

namespace Allkiri\Container;

use Allkiri\Xades\Dsig\Xml;
use Allkiri\Xades\Ns;
use Allkiri\Xades\SignatureDocument;
use Allkiri\Xades\SignatureStructureException;

/**
 * META-INF/manifest.xml: the OASIS manifest an ASiC-E container carries,
 * listing the container itself and every data file with its media type.
 */
final readonly class Manifest
{
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
            $document = SignatureDocument::parse($xml);
        } catch (SignatureStructureException $e) {
            throw new InvalidContainerException('META-INF/manifest.xml is not well-formed: ' . $e->getMessage(), 0, $e);
        }
        $root = $document->document()->documentElement;
        if ($root === null || $root->localName !== 'manifest') {
            throw new InvalidContainerException('META-INF/manifest.xml has no manifest element');
        }
        $xpath = Xml::xpath($document->document());
        $xpath->registerNamespace('manifest', Ns::MANIFEST);

        $entries = [];
        foreach (Xml::elements($xpath, 'manifest:file-entry', $root) as $entry) {
            $path = $entry->getAttributeNS(Ns::MANIFEST, 'full-path');
            $type = $entry->getAttributeNS(Ns::MANIFEST, 'media-type');
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
            . '<manifest:manifest xmlns:manifest="' . Ns::MANIFEST . '" manifest:version="1.2">'
            . '<manifest:file-entry manifest:full-path="/" manifest:media-type="' . Ns::MIME_ASICE . '"/>';
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

    private static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_XML1, 'UTF-8');
    }
}
