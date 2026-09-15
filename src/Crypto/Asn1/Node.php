<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Asn1;

use phpseclib3\File\ASN1 as PhpseclibAsn1;
use phpseclib3\Math\BigInteger;

/**
 * One element of a raw phpseclib decodeBER tree, bound to the buffer it was
 * decoded from, so the exact DER bytes of any element can be sliced.
 *
 * phpseclib facts this relies on: `length` includes the header; `start` is
 * absolute within the decoded buffer; context-specific elements carry a
 * `constant` key (their tag) while universal ones do not; times decode to
 * DateTime, integers to BigInteger, OIDs to dotted strings.
 *
 * @internal
 */
final class Node
{
    /**
     * @param array<string, mixed> $node
     */
    public function __construct(
        private readonly array $node,
        private readonly string $buffer,
    ) {}

    /**
     * Exact DER of this element, header included.
     */
    public function der(): string
    {
        return substr($this->buffer, $this->int('start'), $this->int('length'));
    }

    /**
     * The element's content bytes without its tag and length header.
     */
    public function contentDer(): string
    {
        $header = $this->int('headerlength');

        return substr($this->buffer, $this->int('start') + $header, $this->int('length') - $header);
    }

    /**
     * Universal type (PhpseclibAsn1::TYPE_*) for universal elements. For tagged
     * elements this is the class number; check {@see isTagged()} first.
     */
    public function type(): int
    {
        return $this->int('type');
    }

    /**
     * True for context-specific (or application / private class) elements.
     */
    public function isTagged(): bool
    {
        return \array_key_exists('constant', $this->node);
    }

    /**
     * The tag number of a context-specific element ([0], [1], ...).
     */
    public function tag(): int
    {
        if (!$this->isTagged()) {
            throw new Asn1Exception('Element is not tagged');
        }

        return $this->int('constant');
    }

    public function isSequence(): bool
    {
        return !$this->isTagged() && $this->type() === PhpseclibAsn1::TYPE_SEQUENCE;
    }

    public function isConstructed(): bool
    {
        return \is_array($this->node['content'] ?? null);
    }

    /**
     * @return list<Node>
     */
    public function children(): array
    {
        $content = $this->node['content'] ?? null;
        if (!\is_array($content)) {
            throw new Asn1Exception('Element is primitive and has no children');
        }
        $children = [];
        foreach ($content as $child) {
            if (!\is_array($child)) {
                throw new Asn1Exception('Malformed decoded element');
            }
            /** @var array<string, mixed> $child */
            $children[] = new self($child, $this->buffer);
        }

        return $children;
    }

    public function child(int $index): Node
    {
        return $this->children()[$index] ?? throw new Asn1Exception(\sprintf('Element has no child %d', $index));
    }

    public function childCount(): int
    {
        return \count($this->children());
    }

    /**
     * First child that is a context-specific element with the given tag.
     */
    public function tagged(int $tag): ?Node
    {
        foreach ($this->children() as $child) {
            if ($child->isTagged() && $child->tag() === $tag) {
                return $child;
            }
        }

        return null;
    }

    /**
     * Content of OCTET STRING, UTF8String and other string-like primitives,
     * and the raw content of primitive tagged elements.
     */
    public function string(): string
    {
        $content = $this->node['content'] ?? null;
        if (!\is_string($content)) {
            throw new Asn1Exception('Element is not a string primitive');
        }

        return $content;
    }

    /**
     * BIT STRING content without the leading unused-bits octet.
     */
    public function bitStringBytes(): string
    {
        if ($this->isTagged() || $this->type() !== PhpseclibAsn1::TYPE_BIT_STRING) {
            throw new Asn1Exception('Element is not a BIT STRING');
        }
        $content = $this->string();
        if ($content === '') {
            throw new Asn1Exception('Empty BIT STRING');
        }

        return substr($content, 1);
    }

    public function oid(): string
    {
        if ($this->isTagged() || $this->type() !== PhpseclibAsn1::TYPE_OBJECT_IDENTIFIER) {
            throw new Asn1Exception('Element is not an OBJECT IDENTIFIER');
        }

        return Oids::dotted($this->string());
    }

    public function integer(): BigInteger
    {
        $content = $this->node['content'] ?? null;
        if (!$content instanceof BigInteger) {
            throw new Asn1Exception('Element is not an INTEGER');
        }

        return $content;
    }

    public function boolean(): bool
    {
        $content = $this->node['content'] ?? null;
        if (!\is_bool($content)) {
            throw new Asn1Exception('Element is not a BOOLEAN');
        }

        return $content;
    }

    /**
     * UTCTime / GeneralizedTime as an immutable UTC instant.
     */
    public function time(): \DateTimeImmutable
    {
        $content = $this->node['content'] ?? null;
        if (!$content instanceof \DateTimeInterface) {
            throw new Asn1Exception('Element is not a time value');
        }

        return \DateTimeImmutable::createFromInterface($content)->setTimezone(new \DateTimeZone('UTC'));
    }

    /**
     * Decode this element's DER against a map (for ANY / nested structures).
     *
     * @param array<string, mixed> $map
     */
    public function map(array $map): DecodedElement
    {
        return Asn1::decode($this->der(), $map);
    }

    /**
     * @return array<string, mixed> the underlying phpseclib node
     */
    public function raw(): array
    {
        return $this->node;
    }

    private function int(string $key): int
    {
        $value = $this->node[$key] ?? null;
        if (!\is_int($value)) {
            throw new Asn1Exception(\sprintf('Decoded element lacks "%s"', $key));
        }

        return $value;
    }
}
