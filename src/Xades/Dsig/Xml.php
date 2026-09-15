<?php

declare(strict_types=1);

namespace Allkiri\Xades\Dsig;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Xades\Ns;

/**
 * XPath helpers that turn ext-dom's loosely typed results into definite ones,
 * so the signature code reads as intent rather than as null handling.
 */
final class Xml
{
    private function __construct() {}

    /**
     * An XPath bound to the node's document with allkiri's prefixes registered.
     */
    public static function xpath(\DOMNode $context): \DOMXPath
    {
        $document = $context instanceof \DOMDocument ? $context : $context->ownerDocument;
        if ($document === null) {
            throw new InvalidArgumentException('The node belongs to no document, so it cannot be searched');
        }
        $xpath = new \DOMXPath($document);
        $xpath->registerNamespace('ds', Ns::DS);
        $xpath->registerNamespace('xades', Ns::XADES);
        $xpath->registerNamespace('xadesv141', Ns::XADES141);
        $xpath->registerNamespace('asic', Ns::ASIC);
        $xpath->registerNamespace('ec', Ns::C14N_EXC);

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
