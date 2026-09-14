<?php

declare(strict_types=1);

namespace Allkiri\Xades\Lta;

use Allkiri\Xades\Dsig\Canonicalizer;
use Allkiri\Xades\Dsig\ReferenceResolver;
use Allkiri\Xades\Dsig\Xml;
use Allkiri\Xades\Ns;
use Allkiri\Xades\XadesException;

/**
 * What an archive timestamp covers.
 *
 * An archive timestamp is what keeps a signature verifiable after the signer's
 * own algorithms weaken or their certificate's chain expires: it re-stamps
 * everything, including the earlier timestamp and the revocation data, so the
 * whole assembly has a fresh proof of existence. That means the octet stream it
 * is computed over has to be reproduced exactly, years later, by a different
 * implementation. This class is the one place that stream is built, and both
 * making a signature and checking one go through it.
 *
 * The construction follows ETSI EN 319 132-1 clause 5.5.2.2, in five steps:
 *
 * 1. every `ds:Reference` of `ds:SignedInfo`, in order, dereferenced —
 *    **including** the one covering `SignedProperties`;
 * 2. `ds:SignedInfo`, `ds:SignatureValue` and `ds:KeyInfo` if present;
 * 3. each unsigned signature property appearing before this archive timestamp,
 *    in document order;
 * 4. every `ds:Object` except the one holding `xades:QualifyingProperties`;
 * 5. all of it canonicalised with the algorithm the archive timestamp declares.
 *
 * The first step is the one worth stating plainly, because leaving the
 * SignedProperties reference out produces a stream that looks entirely
 * reasonable and matches nothing: the clause says "including the
 * SignedProperties element", where the signature timestamp's own computation
 * does not.
 */
final class ArchiveTimestampData
{
    public function __construct(
        private readonly Canonicalizer $canonicalizer = new Canonicalizer(),
    ) {}

    /**
     * Build the stream for an archive timestamp that is about to be added,
     * covering everything currently in the signature.
     */
    public function forNewTimestamp(\DOMElement $signature, ReferenceResolver $resolver, string $canonicalization = Ns::C14N_EXC): string
    {
        return $this->build($signature, $resolver, $canonicalization, null);
    }

    /**
     * Build the stream an existing archive timestamp should have been computed
     * over, so its imprint can be checked.
     *
     * @param \DOMElement $archiveTimestamp the `xadesv141:ArchiveTimeStamp` element
     */
    public function forExistingTimestamp(\DOMElement $signature, \DOMElement $archiveTimestamp, ReferenceResolver $resolver): string
    {
        return $this->build($signature, $resolver, self::canonicalizationOf($archiveTimestamp), $archiveTimestamp);
    }

    /**
     * The canonicalisation an archive timestamp declares.
     *
     * XML-DSig's own default is inclusive canonicalisation, and that is what
     * applies when the element says nothing, even though everything Estonian
     * uses exclusive and says so.
     */
    public static function canonicalizationOf(\DOMElement $archiveTimestamp): string
    {
        foreach ($archiveTimestamp->childNodes as $child) {
            if ($child instanceof \DOMElement && $child->localName === 'CanonicalizationMethod' && $child->namespaceURI === Ns::DS) {
                $algorithm = $child->getAttribute('Algorithm');
                if ($algorithm !== '') {
                    return $algorithm;
                }
            }
        }

        return Ns::C14N_10;
    }

    /**
     * @param \DOMElement|null $stopAt the archive timestamp being checked, or null
     *                                 when adding a new one at the end
     */
    private function build(\DOMElement $signature, ReferenceResolver $resolver, string $canonicalization, ?\DOMElement $stopAt): string
    {
        $document = $signature->ownerDocument;
        if ($document === null) {
            throw new XadesException('The signature is not part of a document');
        }
        $xpath = Xml::xpath($document);

        $stream = '';

        // 1. Everything ds:SignedInfo references, in order, including the
        //    SignedProperties. A same-document reference contributes the
        //    canonicalised element; an external one its bytes as they are.
        foreach (Xml::elements($xpath, './ds:SignedInfo/ds:Reference', $signature) as $reference) {
            $stream .= $this->referencedBytes($xpath, $reference, $resolver, $canonicalization);
        }

        // 2. The signature's own elements.
        foreach (['SignedInfo', 'SignatureValue', 'KeyInfo'] as $name) {
            $element = $this->child($signature, Ns::DS, $name);
            if ($element !== null) {
                $stream .= $this->canonicalizer->canonicalize($element, $canonicalization);
            }
        }

        // 3. The unsigned properties already there, up to this timestamp.
        $stream .= $this->unsignedProperties($xpath, $signature, $canonicalization, $stopAt);

        // 4. Any ds:Object that is not the one holding the qualifying properties.
        foreach (Xml::elements($xpath, './ds:Object', $signature) as $object) {
            if (Xml::elements($xpath, './xades:QualifyingProperties', $object) !== []) {
                continue;
            }
            $stream .= $this->canonicalizer->canonicalize($object, $canonicalization);
        }

        return $stream;
    }

    private function referencedBytes(\DOMXPath $xpath, \DOMElement $reference, ReferenceResolver $resolver, string $canonicalization): string
    {
        $uri = $reference->getAttribute('URI');

        if ($uri === '' || str_starts_with($uri, '#')) {
            $document = $reference->ownerDocument;
            $elements = $document === null || $uri === ''
                ? []
                : Xml::elementsById($document, substr($uri, 1));
            if (\count($elements) > 1) {
                throw new XadesException(\sprintf('An archive timestamp covers reference "%s", and %d elements carry that Id', $uri, \count($elements)));
            }
            if ($elements === []) {
                throw new XadesException(\sprintf('An archive timestamp covers reference "%s", which resolves to nothing', $uri));
            }

            return $this->canonicalizer->canonicalize($elements[0], $canonicalization);
        }

        $bytes = $resolver->resolve(rawurldecode($uri));
        if ($bytes === null) {
            throw new XadesException(\sprintf('An archive timestamp covers "%s", which is not in the container', rawurldecode($uri)));
        }

        return $bytes;
    }

    private function unsignedProperties(\DOMXPath $xpath, \DOMElement $signature, string $canonicalization, ?\DOMElement $stopAt): string
    {
        $containers = Xml::elements(
            $xpath,
            './ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties',
            $signature,
        );
        if ($containers === []) {
            return '';
        }

        $stream = '';
        foreach ($containers[0]->childNodes as $child) {
            if (!$child instanceof \DOMElement) {
                continue;
            }
            if ($stopAt !== null && $child->isSameNode($stopAt)) {
                break;
            }
            $stream .= $this->canonicalizer->canonicalize($child, $canonicalization);
        }

        return $stream;
    }

    private function child(\DOMElement $parent, string $namespace, string $localName): ?\DOMElement
    {
        foreach ($parent->childNodes as $child) {
            if ($child instanceof \DOMElement && $child->localName === $localName && $child->namespaceURI === $namespace) {
                return $child;
            }
        }

        return null;
    }
}
