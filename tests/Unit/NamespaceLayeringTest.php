<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit;

use Allkiri\Tests\Support\SourceTree;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * The parts of the library form one graph without cycles, and the table below
 * is that graph: each part of src, and the parts it may refer to.
 *
 * A reference is an import, a qualified or fully qualified name, or an Allkiri
 * class named in a comment, because a {@see} pointing elsewhere is a dependency
 * a reader follows too. A new dependency is added to the table, where a cycle
 * shows at once.
 */
#[CoversNothing]
final class NamespaceLayeringTest extends TestCase
{
    /**
     * Lowest first; a part refers only to parts listed before it.
     */
    private const ALLOWED = [
        'Exception' => [],
        'Clock' => [],
        'Resources' => ['Exception'],
        'Http' => ['Exception'],
        'Crypto' => ['Exception', 'Http'],
        'StoredData' => ['Crypto', 'Exception'],
        'Auth' => ['Crypto', 'Exception'],
        'Xml' => ['Crypto', 'Exception'],
        'Container' => ['Crypto', 'Exception', 'Xml'],
        'Trust' => ['Crypto', 'Exception', 'Http', 'Xml'],
        'Xades' => ['Container', 'Crypto', 'Exception', 'Xml'],
        'Config' => ['Crypto', 'Resources', 'Trust'],
        'Signing' => ['Container', 'Crypto', 'Exception', 'StoredData', 'Trust', 'Xades', 'Xml'],
        'Validation' => ['Container', 'Crypto', 'Exception', 'Http', 'Signing', 'Trust', 'Xades', 'Xml'],
        'MobileId' => ['Auth', 'Clock', 'Container', 'Crypto', 'Exception', 'Http', 'Signing', 'StoredData', 'Trust'],
        'SmartId' => ['Auth', 'Clock', 'Container', 'Crypto', 'Exception', 'Http', 'Signing', 'StoredData', 'Trust'],
        'WebEid' => ['Auth', 'Clock', 'Container', 'Crypto', 'Exception', 'Http', 'Signing', 'StoredData', 'Trust'],
        'Allkiri' => ['Clock', 'Config', 'Container', 'Crypto', 'Http', 'MobileId', 'Signing', 'SmartId', 'Trust', 'Validation', 'WebEid'],
    ];

    public function testEveryPartOfSrcHasARowInTheTable(): void
    {
        $parts = [];
        foreach (SourceTree::classes() as $class) {
            $part = self::partOf($class);
            if (!\in_array($part, $parts, true)) {
                $parts[] = $part;
            }
        }
        sort($parts);
        $rows = array_keys(self::allowed());
        sort($rows);

        self::assertSame($parts, $rows);
    }

    public function testTheTableHasNoCycle(): void
    {
        $remaining = self::allowed();
        $placed = [];
        do {
            $progress = false;
            foreach ($remaining as $part => $uses) {
                if (array_diff($uses, $placed) === []) {
                    $placed[] = $part;
                    unset($remaining[$part]);
                    $progress = true;
                }
            }
        } while ($progress);

        self::assertSame([], array_keys($remaining), 'these parts refer to each other in a circle');
    }

    public function testNoReferenceGoesOutsideTheTable(): void
    {
        $allowed = self::allowed();
        $outside = [];
        foreach (self::references() as $from => $targets) {
            foreach ($targets as $to => $places) {
                if (!\in_array($to, $allowed[$from] ?? [], true)) {
                    $outside[] = \sprintf('%s -> %s at %s', $from, $to, implode(', ', \array_slice($places, 0, 3)));
                }
            }
        }

        self::assertSame([], $outside);
    }

    public function testEveryDependencyInTheTableIsUsed(): void
    {
        $references = self::references();
        $unused = [];
        foreach (self::allowed() as $from => $uses) {
            foreach ($uses as $to) {
                if (!isset($references[$from][$to])) {
                    $unused[] = $from . ' -> ' . $to;
                }
            }
        }

        self::assertSame([], $unused, 'the table allows what nothing uses; remove it');
    }

    public function testTheReaderFindsEveryKindOfReference(): void
    {
        $source = <<<'PHP'
            <?php
            namespace Allkiri\Http;

            use Allkiri\Crypto\Certificate;
            use Allkiri\Container as Zip;

            /** Built with {@see \Allkiri\Validation\ValidationPolicy}. */
            final class Example
            {
                public function run(): void
                {
                    \Allkiri\Signing\SigningService::class;
                    Zip\AsicReader::class;
                    Local\Thing::class;
                    "{$this->Allkiri}";
                }
            }
            PHP;

        self::assertSame([
            'Allkiri\Crypto\Certificate',
            'Allkiri\Container',
            'Allkiri\Validation\ValidationPolicy',
            'Allkiri\Signing\SigningService',
            'Allkiri\Container\AsicReader',
            'Allkiri\Http\Local\Thing',
        ], array_column(SourceTree::referencesIn($source, ['StoredData']), 0));

        $root = <<<'PHP'
            <?php
            namespace Allkiri;

            final class Facade
            {
                public function run(): void
                {
                    StoredData::restore();
                    $this->StoredData;
                }
            }
            PHP;

        self::assertSame(['Allkiri\StoredData'], array_column(SourceTree::referencesIn($root, ['StoredData']), 0));
    }

    /**
     * @return array<string, list<string>>
     */
    private static function allowed(): array
    {
        return self::ALLOWED;
    }

    /**
     * The part of the library a class belongs to: the first namespace below
     * Allkiri, or the class itself when it sits directly in src.
     */
    private static function partOf(string $class): string
    {
        $segments = explode('\\', $class);

        return $segments[1] ?? $segments[0];
    }

    /**
     * @return array<string, array<string, list<string>>> part => part it refers to => where, as "file:line name"
     */
    private static function references(): array
    {
        $root = SourceTree::root();
        $classes = SourceTree::classes();
        $rootClasses = [];
        foreach ($classes as $class) {
            if (substr_count($class, '\\') === 1) {
                $rootClasses[] = self::partOf($class);
            }
        }

        $references = [];
        foreach ($classes as $path => $class) {
            $from = self::partOf($class);
            $file = str_replace('\\', '/', substr($path, \strlen($root) + 1));
            foreach (SourceTree::referencesIn((string) file_get_contents($path), $rootClasses) as [$name, $line]) {
                if (!str_starts_with($name, 'Allkiri\\')) {
                    continue;
                }
                $to = self::partOf($name);
                if ($to !== $from) {
                    $references[$from][$to][] = $file . ':' . $line . ' ' . $name;
                }
            }
        }

        return $references;
    }
}
