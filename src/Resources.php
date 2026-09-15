<?php

declare(strict_types=1);

namespace Allkiri;

use Allkiri\Exception\InvalidArgumentException;

/**
 * Files shipped with the library: the trust anchors and trusted-list signer
 * certificates that a configuration pins.
 */
final class Resources
{
    private function __construct() {}

    public static function path(string $relative): string
    {
        return \dirname(__DIR__) . '/resources/' . $relative;
    }

    public static function read(string $relative): string
    {
        $path = self::path($relative);
        $content = @file_get_contents($path);
        if ($content === false) {
            throw new InvalidArgumentException(\sprintf('There is no bundled resource "%s"; the name is wrong or the package is incomplete', $relative));
        }

        return $content;
    }
}
