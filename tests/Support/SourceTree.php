<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support;

/**
 * The library's source files, for tests that read the code rather than run it.
 */
final class SourceTree
{
    private function __construct() {}

    public static function root(): string
    {
        return (string) realpath(__DIR__ . '/../../src');
    }

    /**
     * @return array<string, string> absolute path => the class the file declares, for every PHP file in src
     */
    public static function classes(): array
    {
        $root = self::root();
        $classes = [];
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS)) as $file) {
            if (!$file instanceof \SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }
            $relative = substr((string) $file->getRealPath(), \strlen($root) + 1, -4);
            $classes[(string) $file->getRealPath()] = 'Allkiri\\' . str_replace(['/', '\\'], '\\', $relative);
        }
        ksort($classes);

        return $classes;
    }
}
