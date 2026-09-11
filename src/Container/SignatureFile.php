<?php

declare(strict_types=1);

namespace Allkiri\Container;

use Allkiri\Exception\InvalidArgumentException;

/**
 * One META-INF/signatures*.xml entry of a container.
 */
final readonly class SignatureFile
{
    public function __construct(
        public string $name,
        public string $xml,
    ) {
        if (preg_match('#^META-INF/signatures\d*\.xml$#', $name) !== 1) {
            throw new InvalidArgumentException(\sprintf('"%s" is not a valid ASiC-E signature file name', $name));
        }
    }

    /**
     * The index in "META-INF/signatures{N}.xml", or null when the name has none.
     */
    public function index(): ?int
    {
        if (preg_match('#^META-INF/signatures(\d+)\.xml$#', $this->name, $match) === 1) {
            return (int) $match[1];
        }

        return null;
    }
}
