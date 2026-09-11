<?php

declare(strict_types=1);

namespace Allkiri\Xades\Dsig;

use Allkiri\Xades\CanonicalizationException;
use Allkiri\Xades\Ns;

/**
 * XML canonicalisation on ext-dom. Exclusive C14N 1.0 is what allkiri emits
 * and what DSS, digidoc4j and libdigidocpp produce for ASiC-E; inclusive
 * C14N 1.0 appears in older signatures and in trusted lists.
 */
final class Canonicalizer
{
    /**
     * @param list<string>|null $inclusiveNamespacePrefixes the InclusiveNamespaces PrefixList of an exclusive transform
     */
    public function canonicalize(\DOMNode $node, string $algorithm, ?array $inclusiveNamespacePrefixes = null): string
    {
        [$exclusive, $withComments] = match ($algorithm) {
            Ns::C14N_EXC => [true, false],
            Ns::C14N_EXC_WITH_COMMENTS => [true, true],
            Ns::C14N_10 => [false, false],
            Ns::C14N_10_WITH_COMMENTS => [false, true],
            default => throw new CanonicalizationException(\sprintf('Unsupported canonicalization algorithm "%s"', $algorithm)),
        };
        $prefixes = $exclusive && $inclusiveNamespacePrefixes !== null && $inclusiveNamespacePrefixes !== [] ? $inclusiveNamespacePrefixes : null;
        $result = $node->C14N($exclusive, $withComments, null, $prefixes);
        if (!\is_string($result)) {
            throw new CanonicalizationException('Canonicalization failed');
        }

        return $result;
    }

    public static function supports(string $algorithm): bool
    {
        return \in_array($algorithm, [Ns::C14N_EXC, Ns::C14N_EXC_WITH_COMMENTS, Ns::C14N_10, Ns::C14N_10_WITH_COMMENTS], true);
    }
}
