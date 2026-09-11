<?php

declare(strict_types=1);

namespace Allkiri\Container;

use Allkiri\Container\Zip\ZipWriter;
use Allkiri\Xades\Ns;

/**
 * Writes an ASiC-E container.
 *
 * A container that was read keeps every original entry byte for byte and only
 * gains the new signature files at the end; a new container is written in the
 * order the format requires, mimetype first and uncompressed.
 */
final class AsicWriter
{
    public function write(AsicContainer $container): string
    {
        $zip = new ZipWriter();

        if ($container->isNew()) {
            $zip->addStored(AsicReader::MIMETYPE_ENTRY, Ns::MIME_ASICE);
            foreach ($container->dataFiles as $file) {
                $zip->addDeflated($file->name, $file->content);
            }
            $zip->addDeflated(AsicReader::MANIFEST_ENTRY, $container->manifest->toXml());
        } else {
            foreach ($container->originalEntries as $entry) {
                $zip->addEntry($entry);
            }
        }

        foreach ($container->signatureFiles as $file) {
            if (!$zip->has($file->name)) {
                $zip->addDeflated($file->name, $file->xml);
            }
        }

        return $zip->build();
    }

    public function writeFile(AsicContainer $container, string $path): void
    {
        if (@file_put_contents($path, $this->write($container)) === false) {
            throw new ContainerException(\sprintf('Could not write "%s"', $path));
        }
    }
}
