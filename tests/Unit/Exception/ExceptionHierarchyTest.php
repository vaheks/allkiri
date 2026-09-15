<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Exception;

use Allkiri\Exception\AllkiriException;
use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Http\CurlHttpClient;
use Allkiri\Xades\Model\XadesSignatureParser;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * One family, which can be caught the way PHP developers expect: every
 * exception the library throws is an AllkiriException, a programmer error is
 * also SPL's InvalidArgumentException, and everything else is a
 * RuntimeException.
 */
#[CoversNothing]
final class ExceptionHierarchyTest extends TestCase
{
    /**
     * @return array<string, string> source path => class name, for every file in src
     */
    private static function sources(): array
    {
        $root = (string) realpath(__DIR__ . '/../../../src');
        $sources = [];
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS)) as $file) {
            if (!$file instanceof \SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }
            $relative = substr((string) $file->getRealPath(), \strlen($root) + 1, -4);
            $sources[(string) $file->getRealPath()] = 'Allkiri\\' . str_replace(['/', '\\'], '\\', $relative);
        }

        return $sources;
    }

    /**
     * @return iterable<string, array{class-string<\Throwable>}>
     */
    public static function exceptions(): iterable
    {
        foreach (self::sources() as $class) {
            if (class_exists($class) && is_subclass_of($class, \Throwable::class)) {
                yield $class => [$class];
            }
        }
    }

    /**
     * @param class-string<\Throwable> $class
     */
    #[DataProvider('exceptions')]
    public function testEveryLibraryExceptionIsAnAllkiriException(string $class): void
    {
        self::assertTrue(is_subclass_of($class, AllkiriException::class), $class . ' does not implement AllkiriException');

        // Programmer errors are SPL's InvalidArgumentException, and so a LogicException; everything else fails at run time.
        $parent = $class === InvalidArgumentException::class ? \InvalidArgumentException::class : \RuntimeException::class;
        self::assertTrue(is_subclass_of($class, $parent), \sprintf('%s is not a %s', $class, $parent));
    }

    public function testAProgrammerErrorIsCaughtAsAnSplInvalidArgumentException(): void
    {
        try {
            new CurlHttpClient(0);
            self::fail('A zero timeout was accepted');
        } catch (\InvalidArgumentException $exception) {
            self::assertInstanceOf(AllkiriException::class, $exception);
        }
    }

    public function testASignatureOutsideAnyDocumentIsAProgrammerError(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('belongs to no document');

        (new XadesSignatureParser())->parse(new \DOMElement('Signature'));
    }

    /**
     * An SPL exception or an anonymous exception class could not be caught as
     * the library's.
     */
    public function testNothingInSrcCreatesAnExceptionOutsideTheFamily(): void
    {
        $offenders = [];
        foreach (array_keys(self::sources()) as $path) {
            $tokens = array_values(\PhpToken::tokenize((string) file_get_contents($path)));
            foreach ($tokens as $index => $token) {
                if (!$token->is(T_NEW)) {
                    continue;
                }
                $next = self::nextMeaningful($tokens, $index);
                if ($next === null) {
                    continue;
                }
                $where = basename($path) . ':' . $token->line;
                if ($next->is(T_CLASS)) {
                    for ($i = $index + 1; $i < \count($tokens) && $tokens[$i]->text !== '{'; ++$i) {
                        if ($tokens[$i]->is(T_EXTENDS)) {
                            $offenders[] = $where . ' anonymous class';
                        }
                    }
                    continue;
                }
                $name = ltrim($next->text, '\\');
                if ($next->is(T_NAME_FULLY_QUALIFIED) && class_exists($name) && is_subclass_of($name, \Throwable::class) && !is_subclass_of($name, AllkiriException::class)) {
                    $offenders[] = $where . ' ' . $name;
                }
            }
        }

        self::assertSame([], $offenders);
    }

    /**
     * @param list<\PhpToken> $tokens
     */
    private static function nextMeaningful(array $tokens, int $index): ?\PhpToken
    {
        for ($i = $index + 1; $i < \count($tokens); ++$i) {
            if (!$tokens[$i]->isIgnorable()) {
                return $tokens[$i];
            }
        }

        return null;
    }
}
