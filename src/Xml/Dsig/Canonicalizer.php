<?php

declare(strict_types=1);

namespace Allkiri\Xml\Dsig;

/**
 * XML canonicalisation on ext-dom. Exclusive C14N 1.0 is what allkiri emits
 * and what DSS and digidoc4j produce for ASiC-E; libdigidocpp, and so
 * DigiDoc4, signs with C14N 1.1; inclusive C14N 1.0 appears in older
 * signatures and in trusted lists.
 *
 * @internal
 */
final class Canonicalizer
{
    private const XML_NAMESPACE = 'http://www.w3.org/XML/1998/namespace';

    /**
     * @param list<string>|null $inclusiveNamespacePrefixes the InclusiveNamespaces PrefixList of an exclusive transform
     */
    public function canonicalize(\DOMNode $node, string $algorithm, ?array $inclusiveNamespacePrefixes = null): string
    {
        [$exclusive, $withComments] = match ($algorithm) {
            DsigNs::C14N_EXC => [true, false],
            DsigNs::C14N_EXC_WITH_COMMENTS => [true, true],
            DsigNs::C14N_10, DsigNs::C14N_11 => [false, false],
            DsigNs::C14N_10_WITH_COMMENTS, DsigNs::C14N_11_WITH_COMMENTS => [false, true],
            default => throw new CanonicalizationException(\sprintf('Unsupported canonicalization algorithm "%s"', $algorithm)),
        };
        if ($algorithm === DsigNs::C14N_11 || $algorithm === DsigNs::C14N_11_WITH_COMMENTS) {
            self::requireSameAsC14n10($node);
        }
        $prefixes = $exclusive && $inclusiveNamespacePrefixes !== null && $inclusiveNamespacePrefixes !== [] ? $inclusiveNamespacePrefixes : null;
        $result = $node->C14N($exclusive, $withComments, null, $prefixes);
        if (!\is_string($result)) {
            throw new CanonicalizationException('Canonicalization failed');
        }

        return $result;
    }

    public static function supports(string $algorithm): bool
    {
        return \in_array($algorithm, [
            DsigNs::C14N_EXC,
            DsigNs::C14N_EXC_WITH_COMMENTS,
            DsigNs::C14N_10,
            DsigNs::C14N_10_WITH_COMMENTS,
            DsigNs::C14N_11,
            DsigNs::C14N_11_WITH_COMMENTS,
        ], true);
    }

    /**
     * ext-dom has no C14N 1.1, and libdigidocpp signs with it. The two differ
     * only in the xml: attributes a subtree takes over from the elements above
     * it: 1.0 copies them all onto the subtree's top element, 1.1 copies
     * xml:lang and xml:space alike but leaves xml:id behind and rewrites
     * xml:base (C14N 1.1, section 2.4). Everything this library canonicalises
     * is a whole subtree, so where no element above it carries xml:id or
     * xml:base the two give the same bytes, and 1.0 is used. Otherwise the
     * signature is refused as unsupported rather than read one way when it
     * was made another.
     *
     * @throws CanonicalizationException
     */
    private static function requireSameAsC14n10(\DOMNode $node): void
    {
        for ($ancestor = $node->parentNode; $ancestor instanceof \DOMElement; $ancestor = $ancestor->parentNode) {
            foreach (['id', 'base'] as $name) {
                if ($ancestor->hasAttributeNS(self::XML_NAMESPACE, $name)) {
                    throw new CanonicalizationException(\sprintf(
                        'C14N 1.1 is supported only where no element above the canonicalised one carries xml:%s, and <%s> does',
                        $name,
                        $ancestor->nodeName,
                    ));
                }
            }
        }
    }
}
