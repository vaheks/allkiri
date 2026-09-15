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
        ], array_column(self::namesIn($source, ['StoredData']), 0));

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

        self::assertSame(['Allkiri\StoredData'], array_column(self::namesIn($root, ['StoredData']), 0));
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
            foreach (self::namesIn((string) file_get_contents($path), $rootClasses) as [$name, $line]) {
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

    /**
     * Every class name a file refers to, resolved against its namespace and
     * imports.
     *
     * @param list<string> $rootClasses the classes directly in src, which a file in the Allkiri namespace names unqualified
     *
     * @return list<array{string, int}> each name, without a leading backslash, and its line
     */
    private static function namesIn(string $source, array $rootClasses): array
    {
        $tokens = [];
        foreach (\PhpToken::tokenize($source) as $token) {
            if (!$token->is(T_WHITESPACE)) {
                $tokens[] = $token;
            }
        }

        $namespace = '';
        $imports = [];
        $names = [];
        $count = \count($tokens);
        for ($i = 0; $i < $count; ++$i) {
            $token = $tokens[$i];

            if ($token->is(T_NAMESPACE)) {
                for (++$i; $i < $count && $tokens[$i]->text !== ';' && $tokens[$i]->text !== '{'; ++$i) {
                    if ($tokens[$i]->is([T_STRING, T_NAME_QUALIFIED])) {
                        $namespace = $tokens[$i]->text;
                    }
                }

                continue;
            }

            if ($token->is(T_USE) && ($i === 0 || !$tokens[$i - 1]->is(T_STRING) && $tokens[$i - 1]->text !== ')')) {
                $name = '';
                $alias = '';
                for (++$i; $i < $count && $tokens[$i]->text !== ';' && $tokens[$i]->text !== '(' && $tokens[$i]->text !== '{'; ++$i) {
                    if ($tokens[$i]->is(T_AS) && $i + 1 < $count) {
                        $alias = $tokens[++$i]->text;
                    } elseif ($name === '' && $tokens[$i]->is([T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED, T_STRING])) {
                        $name = ltrim($tokens[$i]->text, '\\');
                    }
                }
                if ($name !== '') {
                    $segments = explode('\\', $name);
                    $imports[$alias !== '' ? $alias : $segments[\count($segments) - 1]] = $name;
                    $names[] = [$name, $token->line];
                }

                continue;
            }

            if ($token->is(T_NAME_FULLY_QUALIFIED)) {
                $names[] = [ltrim($token->text, '\\'), $token->line];
            } elseif ($token->is(T_NAME_QUALIFIED)) {
                $first = explode('\\', $token->text)[0];
                $names[] = [isset($imports[$first]) ? $imports[$first] . substr($token->text, \strlen($first)) : $namespace . '\\' . $token->text, $token->line];
            } elseif ($token->is([T_DOC_COMMENT, T_COMMENT])) {
                preg_match_all('/(?<![A-Za-z0-9_])Allkiri(?:\\\\[A-Za-z_][A-Za-z0-9_]*)+/', $token->text, $matches, PREG_OFFSET_CAPTURE);
                foreach ($matches[0] as [$name, $offset]) {
                    $names[] = [$name, $token->line + substr_count(substr($token->text, 0, $offset), "\n")];
                }
            } elseif ($namespace === 'Allkiri' && $token->is(T_STRING) && \in_array($token->text, $rootClasses, true)) {
                $previous = $i > 0 ? $tokens[$i - 1] : null;
                if ($previous === null || !$previous->is([T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_CONST, T_CLASS, T_ENUM, T_INTERFACE, T_TRAIT])) {
                    $names[] = ['Allkiri\\' . $token->text, $token->line];
                }
            }
        }

        return $names;
    }
}
