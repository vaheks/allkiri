<?php

declare(strict_types=1);

namespace Allkiri\Xml;

use Allkiri\Exception\InvalidArgumentException;

/**
 * Loads untrusted XML, and turns ext-dom's loosely typed XPath results into
 * definite ones, so the code reading signatures, manifests and trusted lists
 * reads as intent rather than as null handling.
 *
 * @internal
 */
final class Xml
{
    private function __construct() {}

    /**
     * A document parsed without network access, entities or DTDs, with
     * whitespace kept exactly as it is so canonicalisation reproduces what the
     * signer saw.
     *
     * @throws InvalidXmlException when the bytes are empty, not well-formed, or carry a DOCTYPE
     */
    public static function load(string $xml): \DOMDocument
    {
        if ($xml === '') {
            throw new InvalidXmlException('Empty XML document');
        }
        // A cheap early exit, but only for encodings that spell "<!DOCTYPE" in
        // ASCII. The parsed document is checked again below.
        if (preg_match('/<!DOCTYPE/i', $xml) === 1) {
            throw new InvalidXmlException('XML documents with a DOCTYPE are not accepted');
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
            throw new InvalidXmlException('XML is not well-formed' . ($first instanceof \LibXMLError ? ': ' . trim($first->message) : ''));
        }
        // UTF-16 puts a zero byte between the characters of "<!DOCTYPE", so the
        // search above misses it and libxml parses the DTD. Only the parsed
        // document can say whether there was one.
        if ($document->doctype !== null) {
            throw new InvalidXmlException('XML documents with a DOCTYPE are not accepted');
        }

        return $document;
    }

    /**
     * An XPath bound to the node's document, with these prefixes registered and
     * no others.
     *
     * @param array<string, string> $namespaces prefix => namespace URI
     */
    public static function xpath(\DOMNode $context, array $namespaces): \DOMXPath
    {
        $document = $context instanceof \DOMDocument ? $context : $context->ownerDocument;
        if ($document === null) {
            throw new InvalidArgumentException('The node belongs to no document, so it cannot be searched');
        }
        $xpath = new \DOMXPath($document);
        foreach ($namespaces as $prefix => $uri) {
            $xpath->registerNamespace($prefix, $uri);
        }

        return $xpath;
    }

    /**
     * @return list<\DOMNameSpaceNode|\DOMNode>
     */
    public static function nodes(\DOMXPath $xpath, string $query, \DOMNode $context): array
    {
        $found = $xpath->query($query, $context);
        if (!$found instanceof \DOMNodeList) {
            return [];
        }
        $nodes = [];
        foreach ($found as $node) {
            $nodes[] = $node;
        }

        return $nodes;
    }

    /**
     * @return list<\DOMElement>
     */
    public static function elements(\DOMXPath $xpath, string $query, \DOMNode $context): array
    {
        $elements = [];
        foreach (self::nodes($xpath, $query, $context) as $node) {
            if ($node instanceof \DOMElement) {
                $elements[] = $node;
            }
        }

        return $elements;
    }

    public static function element(\DOMXPath $xpath, string $query, \DOMNode $context): ?\DOMElement
    {
        return self::elements($xpath, $query, $context)[0] ?? null;
    }

    /**
     * An attribute value, or the empty string when the attribute is absent.
     */
    public static function attribute(\DOMXPath $xpath, string $query, \DOMNode $context): string
    {
        foreach (self::nodes($xpath, $query, $context) as $node) {
            if ($node instanceof \DOMAttr) {
                return $node->value;
            }
        }

        return '';
    }

    /**
     * @return list<string> the values of every matching attribute, in document order
     */
    public static function attributes(\DOMXPath $xpath, string $query, \DOMNode $context): array
    {
        $values = [];
        foreach (self::nodes($xpath, $query, $context) as $node) {
            if ($node instanceof \DOMAttr) {
                $values[] = $node->value;
            }
        }

        return $values;
    }

    public static function text(\DOMXPath $xpath, string $query, \DOMNode $context): ?string
    {
        return self::element($xpath, $query, $context)?->textContent;
    }

    /**
     * Decoded base64 content of an element, or null when absent or malformed.
     */
    public static function base64(\DOMXPath $xpath, string $query, \DOMNode $context): ?string
    {
        $text = self::text($xpath, $query, $context);
        if ($text === null) {
            return null;
        }

        return self::decodeBase64($text);
    }

    public static function decodeBase64(string $text): ?string
    {
        $decoded = base64_decode((string) preg_replace('/\s+/', '', $text), true);

        return $decoded === false || $decoded === '' ? null : $decoded;
    }

    /**
     * The element carrying this Id, or null when none does or when more than
     * one does.
     *
     * Several elements with one Id make a same-document reference ambiguous: a
     * verifier can digest one of them while a reader is shown another. So no
     * caller gets the first and carries on.
     */
    public static function elementById(\DOMDocument $document, string $id): ?\DOMElement
    {
        $elements = self::elementsById($document, $id);

        return \count($elements) === 1 ? $elements[0] : null;
    }

    /**
     * @return list<\DOMElement> every element carrying this Id, in document order
     */
    public static function elementsById(\DOMDocument $document, string $id): array
    {
        return self::elements(new \DOMXPath($document), \sprintf('//*[@Id=%s]', self::literal($id)), $document);
    }

    /**
     * An XPath string literal, quoted safely whatever the value contains.
     */
    public static function literal(string $value): string
    {
        if (!str_contains($value, "'")) {
            return "'" . $value . "'";
        }
        if (!str_contains($value, '"')) {
            return '"' . $value . '"';
        }

        return "concat('" . str_replace("'", "', \"'\", '", $value) . "')";
    }
}
