<?php

declare(strict_types=1);

namespace Allkiri\Container;

/**
 * Media types for the DataObjectFormat elements a BDOC signature must carry.
 *
 * Deliberately a small table rather than a guess from content: the value is
 * signed, so it must be predictable and stable across platforms.
 */
final class MimeTypes
{
    public const DEFAULT = 'application/octet-stream';

    private const BY_EXTENSION = [
        'txt' => 'text/plain',
        'csv' => 'text/csv',
        'xml' => 'text/xml',
        'html' => 'text/html',
        'htm' => 'text/html',
        'css' => 'text/css',
        'json' => 'application/json',
        'pdf' => 'application/pdf',
        'rtf' => 'application/rtf',
        'zip' => 'application/zip',
        'asice' => 'application/vnd.etsi.asic-e+zip',
        'sce' => 'application/vnd.etsi.asic-e+zip',
        'bdoc' => 'application/vnd.etsi.asic-e+zip',
        'asics' => 'application/vnd.etsi.asic-s+zip',
        'scs' => 'application/vnd.etsi.asic-s+zip',
        'ddoc' => 'application/x-ddoc',
        'cdoc' => 'application/x-cdoc',
        'doc' => 'application/msword',
        'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls' => 'application/vnd.ms-excel',
        'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'ppt' => 'application/vnd.ms-powerpoint',
        'pptx' => 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'odt' => 'application/vnd.oasis.opendocument.text',
        'ods' => 'application/vnd.oasis.opendocument.spreadsheet',
        'odp' => 'application/vnd.oasis.opendocument.presentation',
        'png' => 'image/png',
        'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'gif' => 'image/gif',
        'tif' => 'image/tiff',
        'tiff' => 'image/tiff',
        'bmp' => 'image/bmp',
        'svg' => 'image/svg+xml',
        'webp' => 'image/webp',
    ];

    private function __construct() {}

    public static function guess(string $filename): string
    {
        $dot = strrpos($filename, '.');
        if ($dot === false) {
            return self::DEFAULT;
        }

        return self::BY_EXTENSION[strtolower(substr($filename, $dot + 1))] ?? self::DEFAULT;
    }
}
