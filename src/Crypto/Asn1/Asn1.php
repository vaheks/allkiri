<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Asn1;

use phpseclib3\File\ASN1 as PhpseclibAsn1;
use phpseclib3\File\ASN1\Element;
use phpseclib3\Math\BigInteger;

/**
 * DER in, typed structures out — and back. Thin facade over phpseclib's
 * ASN.1 engine that always keeps the raw tree next to the mapped value.
 */
final class Asn1
{
    private function __construct() {}

    /**
     * Decode exactly one DER element (the whole buffer) against a map.
     *
     * @param array<string, mixed> $map
     */
    public static function decode(string $der, array $map): DecodedElement
    {
        $node = self::decodeRaw($der);
        Oids::register();
        $value = PhpseclibAsn1::asn1map($node->raw(), $map);
        if (!\is_array($value)) {
            throw new Asn1Exception('DER does not match the expected structure');
        }
        /** @var array<string, mixed> $value */

        return new DecodedElement($value, $node);
    }

    /**
     * Decode without a map: the raw element tree of the whole buffer.
     */
    public static function decodeRaw(string $der): Node
    {
        if ($der === '') {
            throw new Asn1Exception('Empty DER');
        }
        NestingGuard::check($der);
        Oids::register();
        $decoded = PhpseclibAsn1::decodeBER($der);
        $root = \is_array($decoded) ? ($decoded[0] ?? null) : null;
        if (!\is_array($root) || \count($decoded) !== 1) {
            throw new Asn1Exception('Not a single DER element');
        }
        /** @var array<string, mixed> $root */
        $node = new Node($root, $der);
        if ($node->der() !== $der) {
            throw new Asn1Exception('DER has trailing bytes');
        }

        return $node;
    }

    /**
     * Encode a value against a map.
     *
     * @param array<string, mixed> $value
     * @param array<string, mixed> $map
     */
    public static function encode(array $value, array $map): string
    {
        Oids::register();

        try {
            $der = PhpseclibAsn1::encodeDER($value, $map);
        } catch (\Throwable $e) {
            throw new Asn1Exception('ASN.1 encoding failed: ' . $e->getMessage(), 0, $e);
        }
        if (!\is_string($der) || $der === '') {
            throw new Asn1Exception('ASN.1 encoding produced no output');
        }

        return $der;
    }

    /**
     * Wrap pre-encoded DER so {@see encode()} copies it verbatim into a structure.
     */
    public static function raw(string $der): Element
    {
        return new Element($der);
    }

    /**
     * Wrap DER in an EXPLICIT context-specific tag: [tag] { der }.
     *
     * Needed because phpseclib copies an {@see Element} verbatim and skips the
     * tagging its map would otherwise apply.
     */
    public static function explicit(int $tag, string $der): string
    {
        return \chr(0xA0 | $tag) . PhpseclibAsn1::encodeLength(\strlen($der)) . $der;
    }

    /**
     * Retag DER with an IMPLICIT context-specific tag, keeping the constructed bit.
     */
    public static function implicit(int $tag, string $der): string
    {
        if ($der === '') {
            throw new Asn1Exception('Cannot retag empty DER');
        }
        $constructed = (\ord($der[0]) & 0x20) !== 0;

        return \chr(0x80 | ($constructed ? 0x20 : 0) | $tag) . substr($der, 1);
    }

    /**
     * SEQUENCE { ...ders } from pre-encoded elements.
     *
     * @param list<string> $ders
     */
    public static function sequence(array $ders): string
    {
        $content = implode('', $ders);

        return "\x30" . PhpseclibAsn1::encodeLength(\strlen($content)) . $content;
    }

    /**
     * SET { ...ders } from pre-encoded elements, in the given order.
     *
     * @param list<string> $ders
     */
    public static function set(array $ders): string
    {
        $content = implode('', $ders);

        return "\x31" . PhpseclibAsn1::encodeLength(\strlen($content)) . $content;
    }

    /**
     * DER INTEGER.
     */
    public static function integer(BigInteger|int|string $value): string
    {
        $big = $value instanceof BigInteger ? $value : new BigInteger((string) $value);
        // phpseclib encodes a BigInteger only inside a mapped structure; wrap, encode, unwrap.
        $wrapped = self::encode(['v' => $big], ['type' => PhpseclibAsn1::TYPE_SEQUENCE, 'children' => ['v' => ['type' => PhpseclibAsn1::TYPE_INTEGER]]]);

        return self::decodeRaw($wrapped)->child(0)->der();
    }

    /**
     * DER of a single primitive of the given universal type (ASN1::TYPE_*),
     * e.g. the OCTET STRING wrapping an OCSP nonce. Integers go through
     * {@see integer()}.
     */
    public static function primitive(int $type, string $content): string
    {
        $der = PhpseclibAsn1::encodeDER($content, ['type' => $type]);
        if (!\is_string($der) || $der === '') {
            throw new Asn1Exception('ASN.1 encoding failed');
        }

        return $der;
    }
}
