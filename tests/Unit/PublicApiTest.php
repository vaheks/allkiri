<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit;

use Allkiri\Tests\Support\SourceTree;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * The version number covers everything in src that is not marked @internal,
 * so the mark has to sit on the machinery and on nothing a caller needs.
 *
 * PHPStan reports a use of something internal only under bleedingEdge, and
 * never between two namespaces with the same root, which rules out this
 * repository's own tests and demo. So the marks are checked here.
 */
#[CoversNothing]
final class PublicApiTest extends TestCase
{
    /**
     * Every class marked @internal, and nothing else. A name ending in \* is
     * every class below that namespace except its exceptions.
     */
    private const INTERNAL = [
        'Allkiri\Clock\PollingLoop',
        'Allkiri\Container\Zip\*',
        'Allkiri\Crypto\Asn1\*',
        'Allkiri\Crypto\Ocsp\OcspRequest',
        'Allkiri\Crypto\Ocsp\OcspResponseVerifier',
        'Allkiri\Crypto\Phpseclib',
        'Allkiri\Crypto\Tsp\PkiStatus',
        'Allkiri\Crypto\Tsp\TimestampRequest',
        'Allkiri\Crypto\Tsp\TimestampResponse',
        'Allkiri\Crypto\Tsp\TimestampTokenVerifier',
        'Allkiri\Http\BoundedBody',
        'Allkiri\Resources',
        'Allkiri\Signing\ContainerReferenceResolver',
        'Allkiri\Signing\LtaExtensionResult',
        'Allkiri\Signing\LtExtensionResult',
        'Allkiri\SmartId\AcspV2Payload',
        'Allkiri\SmartId\SmartIdSessionStatusParser',
        'Allkiri\StoredData',
        'Allkiri\Trust\TrustedList\TrustedListParser',
        'Allkiri\Trust\TrustedList\TrustedListVerifier',
        'Allkiri\Validation\TrustedListExpiry',
        'Allkiri\Xades\BuiltSignature',
        'Allkiri\Xades\Lta\*',
        'Allkiri\Xades\Model\*',
        'Allkiri\Xades\Ns',
        'Allkiri\Xades\SignatureBuilder',
        'Allkiri\Xades\SignatureCompleter',
        'Allkiri\Xades\SignatureDocument',
        'Allkiri\Xml\*',
    ];

    public function testExactlyTheListedClassesAreMarkedInternal(): void
    {
        $wrong = [];
        foreach (self::classes() as $class => $reflection) {
            $listed = self::listed($class, $reflection);
            $marked = self::marked($reflection->getDocComment());
            if ($listed && !$marked) {
                $wrong[] = $class . ' is machinery but not marked @internal';
            } elseif ($marked && !$listed) {
                $wrong[] = $class . ' is marked @internal but not listed here';
            }
        }

        self::assertSame([], $wrong);
    }

    /**
     * A supported member that takes or returns an internal type would put the
     * machinery under the version number after all. The one exception is an
     * optional constructor parameter, which lets a test swap a collaborator;
     * those come after every supported parameter, so the supported ones keep
     * their positions whatever happens to the others.
     */
    public function testNothingSupportedExposesTheMachinery(): void
    {
        $classes = self::classes();
        $internal = self::internalClasses($classes);
        $exposed = [];
        foreach ($classes as $class => $reflection) {
            if (\in_array($class, $internal, true)) {
                continue;
            }
            $scope = SourceTree::scopeOf((string) file_get_contents((string) $reflection->getFileName()));

            foreach ($reflection->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {
                if ($method->getDeclaringClass()->getName() !== $class || self::marked($method->getDocComment())) {
                    continue;
                }
                $doc = (string) $method->getDocComment();
                $firstCollaborator = null;
                foreach ($method->getParameters() as $parameter) {
                    $where = \sprintf('%s::%s() $%s', $class, $method->getName(), $parameter->getName());
                    $leaks = array_values(array_intersect(self::typesOf($parameter->getType(), self::docType($doc, '@param', $parameter->getName()), $scope), $internal));
                    if ($leaks !== [] && $method->isConstructor() && $parameter->isOptional()) {
                        $firstCollaborator ??= $parameter->getName();
                    } elseif ($leaks !== []) {
                        $exposed[] = $where . ' takes ' . implode('|', $leaks);
                    } elseif ($firstCollaborator !== null) {
                        $exposed[] = \sprintf('%s comes after the internal $%s', $where, $firstCollaborator);
                    }
                }
                $leaks = array_values(array_intersect(self::typesOf($method->getReturnType(), self::docType($doc, '@return', null), $scope), $internal));
                if ($leaks !== []) {
                    $exposed[] = \sprintf('%s::%s() returns %s', $class, $method->getName(), implode('|', $leaks));
                }
            }

            foreach ($reflection->getProperties(\ReflectionProperty::IS_PUBLIC) as $property) {
                if ($property->getDeclaringClass()->getName() !== $class) {
                    continue;
                }
                $doc = $property->isPromoted()
                    ? self::docType((string) $reflection->getConstructor()?->getDocComment(), '@param', $property->getName())
                    : self::docType((string) $property->getDocComment(), '@var', null);
                $leaks = array_values(array_intersect(self::typesOf($property->getType(), $doc, $scope), $internal));
                if ($leaks !== []) {
                    $exposed[] = \sprintf('%s::$%s is %s', $class, $property->getName(), implode('|', $leaks));
                }
            }
        }

        self::assertSame([], $exposed);
    }

    public function testTheExamplesUseNothingInternal(): void
    {
        $internal = self::internalClasses(self::classes());
        $examples = (string) realpath(__DIR__ . '/../../examples');
        $used = [];
        foreach (SourceTree::phpFiles($examples) as $path) {
            foreach (SourceTree::referencesIn((string) file_get_contents($path)) as [$name, $line]) {
                if (\in_array($name, $internal, true)) {
                    $used[] = substr($path, \strlen($examples) + 1) . ':' . $line . ' ' . $name;
                }
            }
        }

        self::assertSame([], $used);
    }

    /**
     * @return array<string, \ReflectionClass<object>>
     */
    private static function classes(): array
    {
        $classes = [];
        foreach (SourceTree::classes() as $class) {
            if (class_exists($class) || interface_exists($class) || trait_exists($class)) {
                $classes[$class] = new \ReflectionClass($class);
            }
        }

        return $classes;
    }

    /**
     * @param array<string, \ReflectionClass<object>> $classes
     *
     * @return list<string>
     */
    private static function internalClasses(array $classes): array
    {
        $internal = [];
        foreach ($classes as $class => $reflection) {
            if (self::marked($reflection->getDocComment())) {
                $internal[] = $class;
            }
        }

        return $internal;
    }

    /**
     * @return list<string>
     */
    private static function internalList(): array
    {
        return self::INTERNAL;
    }

    /**
     * @param \ReflectionClass<object> $reflection
     */
    private static function listed(string $class, \ReflectionClass $reflection): bool
    {
        foreach (self::internalList() as $entry) {
            if ($entry === $class) {
                return true;
            }
            if (str_ends_with($entry, '\*') && str_starts_with($class, substr($entry, 0, -1)) && !$reflection->implementsInterface(\Throwable::class)) {
                return true;
            }
        }

        return false;
    }

    private static function marked(string|false $docComment): bool
    {
        return $docComment !== false && preg_match('/(?:^\s*\*|\/\*\*)\s*@internal\b/m', $docComment) === 1;
    }

    /**
     * The class names in a native type and in the matching docblock type.
     *
     * @param array{namespace: string, imports: array<string, string>} $scope
     *
     * @return list<string>
     */
    private static function typesOf(?\ReflectionType $type, ?string $docType, array $scope): array
    {
        $names = [];
        $natives = match (true) {
            $type instanceof \ReflectionNamedType => [$type],
            $type instanceof \ReflectionUnionType, $type instanceof \ReflectionIntersectionType => $type->getTypes(),
            default => [],
        };
        foreach ($natives as $native) {
            if ($native instanceof \ReflectionNamedType && !$native->isBuiltin()) {
                $names[] = $native->getName();
            }
        }
        if ($docType !== null) {
            preg_match_all('/(?<![A-Za-z0-9_\\\\$:-])\\\\?[A-Za-z_][A-Za-z0-9_]*(?:\\\\[A-Za-z_][A-Za-z0-9_]*)*/', $docType, $matches);
            foreach ($matches[0] as $name) {
                $names[] = SourceTree::resolve($name, $scope);
            }
        }

        return array_values(array_unique($names));
    }

    /**
     * The type a docblock gives with this tag, for this parameter when one is
     * named.
     */
    private static function docType(string $docComment, string $tag, ?string $variable): ?string
    {
        foreach (explode("\n", $docComment) as $line) {
            $position = strpos($line, $tag . ' ');
            if ($position === false) {
                continue;
            }
            $rest = ltrim(substr($line, $position + \strlen($tag)));
            $depth = 0;
            $length = \strlen($rest);
            $end = 0;
            for (; $end < $length; ++$end) {
                $character = $rest[$end];
                if ($character === '<' || $character === '{' || $character === '(') {
                    ++$depth;
                } elseif ($character === '>' || $character === '}' || $character === ')') {
                    --$depth;
                } elseif ($depth <= 0 && ($character === ' ' || $character === "\t")) {
                    break;
                }
            }
            $type = substr($rest, 0, $end);
            if ($variable === null || preg_match('/^\s*(?:\.\.\.)?\$' . preg_quote($variable, '/') . '\b/', substr($rest, $end)) === 1) {
                return $type;
            }
        }

        return null;
    }
}
