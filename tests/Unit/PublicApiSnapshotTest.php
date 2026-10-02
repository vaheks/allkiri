<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit;

use Allkiri\Tests\Support\SourceTree;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * The whole supported API, written down: every class, interface and enum not
 * marked @internal, with its constants, cases, public properties and the
 * signatures of its public methods, less the members marked @internal.
 *
 * From 1.0 the version number covers exactly this, so any change to it is a
 * decision: a removal or a changed signature is a major release, an addition a
 * minor one. The test fails on any difference, which puts each one in a
 * review. When the change is meant, write the file again and commit it with
 * the change:
 *
 *     ALLKIRI_UPDATE_API=1 vendor/bin/phpunit tests/Unit/PublicApiSnapshotTest.php
 */
#[CoversNothing]
final class PublicApiSnapshotTest extends TestCase
{
    private const SNAPSHOT = __DIR__ . '/../fixtures/public-api.txt';

    /** `self` in a type or a default, which PHP 8.5 writes out as the class and earlier versions do not. */
    private const SELF = '/\bself\b/';

    public function testTheSupportedApiIsWhatTheSnapshotSays(): void
    {
        $today = self::describe();
        if (getenv('ALLKIRI_UPDATE_API') === '1') {
            file_put_contents(self::SNAPSHOT, $today);
            self::markTestSkipped('The snapshot was written again; review the diff and commit it.');
        }

        self::assertFileExists(self::SNAPSHOT, 'Write it with ALLKIRI_UPDATE_API=1');
        self::assertSame(
            (string) file_get_contents(self::SNAPSHOT),
            $today,
            'The supported API changed. If that is meant, write the snapshot again with ALLKIRI_UPDATE_API=1 and say in the changelog what changed.',
        );
    }

    private static function describe(): string
    {
        $lines = [];
        $classes = SourceTree::classes();
        sort($classes);
        foreach ($classes as $class) {
            if (!class_exists($class) && !interface_exists($class) && !enum_exists($class)) {
                continue;
            }
            $reflection = new \ReflectionClass($class);
            if (self::internal($reflection->getDocComment())) {
                continue;
            }
            $lines[] = self::heading($reflection);
            foreach (self::members($reflection) as $member) {
                $lines[] = '    ' . $member;
            }
            $lines[] = '';
        }

        return implode("\n", $lines);
    }

    /**
     * @param \ReflectionClass<object> $class
     */
    private static function heading(\ReflectionClass $class): string
    {
        $kind = match (true) {
            $class->isEnum() => 'enum',
            $class->isInterface() => 'interface',
            default => ($class->isFinal() ? 'final ' : '') . ($class->isAbstract() ? 'abstract ' : '') . ($class->isReadOnly() ? 'readonly ' : '') . 'class',
        };
        $parent = $class->getParentClass();
        $interfaces = $class->getInterfaceNames();
        sort($interfaces);

        return $kind . ' ' . $class->getName()
            . ($parent !== false ? ' extends ' . $parent->getName() : '')
            . ($interfaces !== [] ? ' implements ' . implode(', ', $interfaces) : '');
    }

    /**
     * @param \ReflectionClass<object> $class
     *
     * @return list<string>
     */
    private static function members(\ReflectionClass $class): array
    {
        $members = [];
        foreach ($class->getReflectionConstants(\ReflectionClassConstant::IS_PUBLIC) as $constant) {
            if ($constant->getDeclaringClass()->getName() !== $class->getName() || self::internal($constant->getDocComment())) {
                continue;
            }
            $members[] = $constant->isEnumCase()
                ? 'case ' . $constant->getName() . self::caseValue($constant->getValue())
                : 'const ' . $constant->getName() . ' = ' . self::export($constant->getValue());
        }
        foreach ($class->getProperties(\ReflectionProperty::IS_PUBLIC) as $property) {
            if ($property->getDeclaringClass()->getName() !== $class->getName() || $property->isStatic() || ($class->isEnum() && \in_array($property->getName(), ['name', 'value'], true))) {
                continue;
            }
            $members[] = 'property ' . ($property->isReadOnly() ? 'readonly ' : '') . self::type($property->getType(), $class) . ' $' . $property->getName();
        }
        $methods = $class->getMethods(\ReflectionMethod::IS_PUBLIC);
        usort($methods, static fn(\ReflectionMethod $a, \ReflectionMethod $b): int => strcmp($a->getName(), $b->getName()));
        foreach ($methods as $method) {
            if ($method->getDeclaringClass()->getName() !== $class->getName() || self::internal($method->getDocComment())) {
                continue;
            }
            if ($class->isEnum() && \in_array($method->getName(), ['cases', 'from', 'tryFrom'], true)) {
                continue;
            }
            $parameters = array_map(static fn(\ReflectionParameter $parameter): string => self::parameter($parameter, $class), $method->getParameters());
            $members[] = ($method->isStatic() ? 'static ' : '') . 'function ' . $method->getName() . '(' . implode(', ', $parameters) . ')'
                . ($method->hasReturnType() ? ': ' . self::type($method->getReturnType(), $class) : '');
        }

        return $members;
    }

    /**
     * @param \ReflectionClass<object> $class
     */
    private static function parameter(\ReflectionParameter $parameter, \ReflectionClass $class): string
    {
        $text = self::type($parameter->getType(), $class) . ($parameter->isVariadic() ? ' ...' : ' ') . '$' . $parameter->getName();
        if ($parameter->isDefaultValueAvailable()) {
            $text .= ' = ' . ($parameter->isDefaultValueConstant() ? (string) preg_replace(self::SELF, $class->getName(), (string) $parameter->getDefaultValueConstantName()) : self::export($parameter->getDefaultValue()));
        }

        return ltrim($text);
    }

    /**
     * PHP 8.5 writes `self` as the class it means and earlier versions write
     * `self`, so it is always written out here, and the snapshot reads the same
     * on every version CI runs.
     *
     * @param \ReflectionClass<object> $class
     */
    private static function type(?\ReflectionType $type, \ReflectionClass $class): string
    {
        return $type === null ? 'mixed' : (string) preg_replace(self::SELF, $class->getName(), (string) $type);
    }

    private static function caseValue(mixed $case): string
    {
        return $case instanceof \BackedEnum ? ' = ' . self::export($case->value) : '';
    }

    private static function export(mixed $value): string
    {
        return match (true) {
            \is_object($value) => $value instanceof \UnitEnum ? $value::class . '::' . $value->name : 'new ' . $value::class . '()',
            \is_array($value) => '[' . implode(', ', array_map(self::export(...), $value)) . ']',
            default => var_export($value, true),
        };
    }

    private static function internal(string|false $docComment): bool
    {
        return $docComment !== false && preg_match('/(?:^\s*\*|\/\*\*)\s*@internal\b/m', $docComment) === 1;
    }
}
