<?php

declare(strict_types=1);

namespace Allkiri\Container;

use Allkiri\Exception\InvalidArgumentException;

/**
 * One META-INF/signatures*.xml entry of a container.
 */
final readonly class SignatureFile
{
    /** The ASiC namespace of the XAdESSignatures element a signature file holds. */
    public const NS_ASIC = 'http://uri.etsi.org/02918/v1.2.1#';

    public function __construct(
        public string $name,
        public string $xml,
    ) {
        // \z, not $: PHP's $ also matches before a trailing newline, and
        // "META-INF/signatures.xml\n" is a name another reader would not treat
        // as a signature file. See AsicReader::isSignatureFileName().
        if (preg_match('#^META-INF/signatures\d*\.xml\z#', $name) !== 1) {
            throw new InvalidArgumentException(\sprintf('"%s" is not a valid ASiC-E signature file name', $name));
        }
    }

    /**
     * The index in "META-INF/signatures{N}.xml", or null when the name has none.
     */
    public function index(): ?int
    {
        if (preg_match('#^META-INF/signatures(\d+)\.xml\z#', $this->name, $match) === 1) {
            return (int) $match[1];
        }

        return null;
    }
}
