<?php

declare(strict_types=1);

namespace Allkiri\Xades;

use Allkiri\Xades\Dsig\Xml;

/**
 * A signatures*.xml document (or any XML carrying ds:Signature elements),
 * loaded without network access, entities or DTDs, with whitespace kept
 * exactly as it is so canonicalisation reproduces what the signer saw.
 */
final class SignatureDocument
{
    private function __construct(private readonly \DOMDocument $document) {}

    public static function parse(string $xml): self
    {
        if ($xml === '') {
            throw new SignatureStructureException('Empty XML document');
        }
        // A cheap early exit, but only for encodings that spell "<!DOCTYPE" in
        // ASCII. The parsed document is checked again below.
        if (preg_match('/<!DOCTYPE/i', $xml) === 1) {
            throw new SignatureStructureException('XML documents with a DOCTYPE are not accepted');
        }
        $document = new \DOMDocument('1.0', 'UTF-8');
        $document->preserveWhiteSpace = true;
        $document->formatOutput = false;
        $previous = libxml_use_internal_errors(true);
        try {
            $ok = $document->loadXML($xml, LIBXML_NONET | LIBXML_NOCDATA);
            $errors = libxml_get_errors();
            libxml_clear_errors();
        } finally {
            libxml_use_internal_errors($previous);
        }
        if (!$ok) {
            $first = $errors[0] ?? null;
            throw new SignatureStructureException('XML is not well-formed' . ($first instanceof \LibXMLError ? ': ' . trim($first->message) : ''));
        }
        // UTF-16 puts a zero byte between the characters of "<!DOCTYPE", so the
        // search above misses it and libxml parses the DTD. Only the parsed
        // document can say whether there was one.
        if ($document->doctype !== null) {
            throw new SignatureStructureException('XML documents with a DOCTYPE are not accepted');
        }

        return new self($document);
    }

    public static function wrap(\DOMDocument $document): self
    {
        return new self($document);
    }

    public function document(): \DOMDocument
    {
        return $this->document;
    }

    public function xpath(): \DOMXPath
    {
        return Xml::xpath($this->document);
    }

    /**
     * @return list<\DOMElement> every ds:Signature in document order
     */
    public function signatures(): array
    {
        $signatures = [];
        foreach ($this->document->getElementsByTagNameNS(Ns::DS, 'Signature') as $element) {
            $signatures[] = $element;
        }

        return $signatures;
    }

    public function signature(string $id): ?\DOMElement
    {
        foreach ($this->signatures() as $signature) {
            if ($signature->getAttribute('Id') === $id) {
                return $signature;
            }
        }

        return null;
    }

    /**
     * Serialised without any reformatting.
     */
    public function toXml(): string
    {
        $xml = $this->document->saveXML();
        if (!\is_string($xml)) {
            throw new SignatureStructureException('Document could not be serialised');
        }

        return $xml;
    }
}
