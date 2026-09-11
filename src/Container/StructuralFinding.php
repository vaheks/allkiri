<?php

declare(strict_types=1);

namespace Allkiri\Container;

/**
 * Something about a container's structure that the validator should report
 * rather than the reader throw: a missing manifest entry, a mimetype in the
 * wrong place. Reading must survive these so a report can explain them.
 */
final readonly class StructuralFinding
{
    public const MIMETYPE_MISSING = 'MIMETYPE_MISSING';
    public const MIMETYPE_NOT_FIRST = 'MIMETYPE_NOT_FIRST';
    public const MIMETYPE_COMPRESSED = 'MIMETYPE_COMPRESSED';
    public const MIMETYPE_HAS_EXTRA_FIELD = 'MIMETYPE_HAS_EXTRA_FIELD';
    public const MIMETYPE_WRONG_CONTENT = 'MIMETYPE_WRONG_CONTENT';
    public const MANIFEST_MISSING = 'MANIFEST_MISSING';
    public const MANIFEST_ENTRY_MISSING_FILE = 'MANIFEST_ENTRY_MISSING_FILE';
    public const FILE_MISSING_MANIFEST_ENTRY = 'FILE_MISSING_MANIFEST_ENTRY';
    public const NO_SIGNATURE_FILES = 'NO_SIGNATURE_FILES';
    public const NO_DATA_FILES = 'NO_DATA_FILES';
    public const UNEXPECTED_META_INF_ENTRY = 'UNEXPECTED_META_INF_ENTRY';

    public function __construct(
        public string $code,
        public string $message,
        public bool $fatal = true,
    ) {}
}
