<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support;

/**
 * The library's source, for tests that read the code rather than run it.
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
        foreach (self::phpFiles($root) as $path) {
            $classes[$path] = 'Allkiri\\' . str_replace(['/', '\\'], '\\', substr($path, \strlen($root) + 1, -4));
        }

        return $classes;
    }

    /**
     * @return list<string> the absolute path of every PHP file below the directory, sorted
     */
    public static function phpFiles(string $directory): array
    {
        $files = [];
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($directory, \FilesystemIterator::SKIP_DOTS)) as $file) {
            if ($file instanceof \SplFileInfo && $file->getExtension() === 'php') {
                $files[] = (string) $file->getRealPath();
            }
        }
        sort($files);

        return $files;
    }

    /**
     * Every class name a file refers to, resolved against its namespace and
     * imports: imports, qualified and fully qualified names, Allkiri classes
     * named in comments, and, in the Allkiri namespace, the classes directly in
     * src named unqualified.
     *
     * @param list<string> $rootClasses the short names of the classes directly in src
     *
     * @return list<array{string, int}> each name, without a leading backslash, and its line
     */
    public static function referencesIn(string $source, array $rootClasses = []): array
    {
        return self::read($source, $rootClasses)['names'];
    }

    /**
     * The namespace a file declares and what it imports, to resolve a name
     * written in it.
     *
     * @return array{namespace: string, imports: array<string, string>}
     */
    public static function scopeOf(string $source): array
    {
        $read = self::read($source, []);

        return ['namespace' => $read['namespace'], 'imports' => $read['imports']];
    }

    /**
     * @param array{namespace: string, imports: array<string, string>} $scope
     */
    public static function resolve(string $name, array $scope): string
    {
        if (str_starts_with($name, '\\')) {
            return substr($name, 1);
        }
        $first = explode('\\', $name)[0];
        if (isset($scope['imports'][$first])) {
            return $scope['imports'][$first] . substr($name, \strlen($first));
        }

        return $scope['namespace'] === '' ? $name : $scope['namespace'] . '\\' . $name;
    }

    /**
     * @param list<string> $rootClasses
     *
     * @return array{namespace: string, imports: array<string, string>, names: list<array{string, int}>}
     */
    private static function read(string $source, array $rootClasses): array
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

            // Not a closure's use, which follows its parameter list.
            if ($token->is(T_USE) && ($i === 0 || $tokens[$i - 1]->text !== ')')) {
                $name = '';
                $alias = '';
                for (++$i; $i < $count && $tokens[$i]->text !== ';' && $tokens[$i]->text !== '{'; ++$i) {
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
                $names[] = [self::resolve($token->text, ['namespace' => $namespace, 'imports' => $imports]), $token->line];
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

        return ['namespace' => $namespace, 'imports' => $imports, 'names' => $names];
    }
}
