<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Asn1;

use phpseclib3\File\ASN1;

/**
 * Refuses DER that would make phpseclib's decoder nest too deep, before
 * phpseclib is given it.
 *
 * phpseclib decodes recursively and copies each element's content at every
 * level, so its memory grows with the square of the depth. Twenty thousand
 * nested SEQUENCEs, about 80 KB, exhaust a 128 MB memory limit, and that is a
 * fatal error: no catch turns it into a refused container or a refused login.
 * Real structures nest a few dozen levels at most.
 *
 * Two things make a plain walk over tags and lengths unsafe.
 *
 * - phpseclib reads BER loosely. It takes a long-form length from the last
 *   four of up to 127 octets, and when a child of a tagged element fails to
 *   decode it stops there, and the enclosing element carries on after it. A
 *   walk that read the bytes more correctly could count fewer levels than
 *   phpseclib descends.
 * - phpseclib decodes some contents again later as DER of their own:
 *   certificate extension values, and public keys. Nesting hidden there is
 *   invisible in the outer structure.
 *
 * So this follows phpseclib 3's decode_ber() step for step, keeping only the
 * lengths, the types and the depth. It also walks the contents of OCTET
 * STRINGs and BIT STRINGs, counting their levels on top of the ones enclosing
 * them. It accepts exactly what phpseclib accepts. The only new refusals are
 * nesting past the limit and, for crafted input, structure too intricate to
 * walk within a budget proportional to its size.
 *
 * NestingGuardTest checks it against an instrumented copy of decode_ber() and
 * fails when a phpseclib upgrade changes that function.
 *
 * @internal
 */
final class NestingGuard
{
    public const MAX_DEPTH = 64;

    /** Headers read so far, against a budget proportional to the input. */
    private int $visits = 0;

    private int $deepest = 0;

    private function __construct(
        private readonly string $der,
        private readonly int $maxDepth,
        private readonly bool $walkContents,
        private readonly int $maxVisits,
    ) {}

    /**
     * @throws Asn1Exception when decoding this DER could nest deeper than the limit
     */
    public static function check(string $der, int $maxDepth = self::MAX_DEPTH): void
    {
        (new self($der, $maxDepth, true, 4096 + 64 * \strlen($der)))->decode(0, \strlen($der), 0, 1);
    }

    /**
     * How deep phpseclib's decodeBER() recurses on this DER, counting every
     * call it makes, successful or not. Contents are not walked, because
     * decodeBER() alone does not decode them.
     */
    public static function depthOf(string $der): int
    {
        $guard = new self($der, \PHP_INT_MAX, false, \PHP_INT_MAX);
        $guard->decode(0, \strlen($der), 0, 1);

        return $guard->deepest;
    }

    /**
     * One call of decode_ber(): the element at $position among the bytes from
     * $base to $end.
     *
     * Returns what decode_ber() would report as the element's length and type,
     * the type being the tag for UNIVERSAL elements and the class for the
     * others. Returns false where decode_ber() returns false.
     *
     * @return array{int, int}|false
     */
    private function decode(int $base, int $end, int $position, int $depth): array|false
    {
        if ($depth > $this->maxDepth) {
            throw new Asn1Exception(\sprintf('DER nests deeper than %d levels', $this->maxDepth));
        }
        if (++$this->visits > $this->maxVisits) {
            throw new Asn1Exception('DER is too intricate to decode safely');
        }
        $this->deepest = max($this->deepest, $depth);

        $size = $end - $base;
        if ($position >= $size) {
            return false;
        }
        $type = \ord($this->der[$base + $position++]);
        // What decode_ber() counts as $start - $current['start'].
        $consumed = 1;
        $constructed = ($type & 0x20) !== 0;
        $tag = $type & 0x1F;
        if ($tag === 0x1F) {
            $tag = 0;
            do {
                if ($position >= $size) {
                    return false;
                }
                $octet = \ord($this->der[$base + $position++]);
                ++$consumed;
                $more = ($octet & 0x80) !== 0;
                $tag <<= 7;
                $octet &= 0x7F;
                if ($consumed === 2 && $octet === 0) {
                    return false;
                }
                $tag |= $octet;
            } while ($more);
        }

        if ($position >= $size) {
            return false;
        }
        $length = \ord($this->der[$base + $position++]);
        ++$consumed;
        $definite = true;
        if ($length === 0x80) {
            $length = $size - $position;
            $definite = false;
        } elseif (($length & 0x80) !== 0) {
            $octets = $length & 0x7F;
            $lengthOctets = $this->slice($base + $position, $end, $octets);
            $position += $octets;
            $consumed += $octets;
            $unpacked = unpack('N', substr(str_pad($lengthOctets, 4, "\0", \STR_PAD_LEFT), -4));
            $length = \is_array($unpacked) && \is_int($unpacked[1] ?? null) ? $unpacked[1] : 0;
        }
        if ($length > $size - $position) {
            return false;
        }
        $contentBase = $base + $position;
        $contentEnd = $contentBase + $length;

        $class = ($type >> 6) & 3;
        if ($class !== ASN1::CLASS_UNIVERSAL) {
            if (!$constructed) {
                return [$consumed + $length, $class];
            }
            $remaining = $length;
            $offset = 0;
            while ($remaining > 0) {
                $child = $this->decode($contentBase, $contentEnd, $offset, $depth + 1);
                if ($child === false) {
                    break;
                }
                // Two zero octets after any child end the element, whether its
                // length was definite or not.
                if ($this->slice($contentBase + $offset + $child[0], $contentEnd, 2) === "\0\0") {
                    $consumed += $child[0] + 2;
                    break;
                }
                $consumed += $child[0];
                $remaining -= $child[0];
                $offset += $child[0];
            }

            return [$consumed, $class];
        }

        switch ($tag) {
            case ASN1::TYPE_BOOLEAN:
                if ($constructed || $length !== 1) {
                    return false;
                }
                break;
            case ASN1::TYPE_INTEGER:
            case ASN1::TYPE_ENUMERATED:
                if ($constructed) {
                    return false;
                }
                break;
            case ASN1::TYPE_REAL:
                return false;
            case ASN1::TYPE_BIT_STRING:
                if (!$constructed) {
                    // A public key, decoded when it is loaded, after the
                    // octet that counts the unused bits.
                    $this->walkContent($contentBase + 1, $contentEnd, $depth);
                    break;
                }
                // decode_ber() decodes the first child, then misreads what it
                // got back and gives up.
                $this->decode($contentBase, $contentEnd, 0, $depth + 1);

                return false;
            case ASN1::TYPE_OCTET_STRING:
                if (!$constructed) {
                    // A certificate extension value, decoded while the
                    // certificate is loaded.
                    $this->walkContent($contentBase, $contentEnd, $depth);
                    break;
                }
                $length = 0;
                $offset = 0;
                while ($this->slice($contentBase + $offset, $contentEnd, 2) !== "\0\0") {
                    $child = $this->decode($contentBase, $contentEnd, $offset, $depth + 1);
                    if ($child === false) {
                        return false;
                    }
                    $offset += $child[0];
                    if ($child[1] !== ASN1::TYPE_OCTET_STRING) {
                        return false;
                    }
                    $length += $child[0];
                }
                $length += 2;
                break;
            case ASN1::TYPE_NULL:
                if ($constructed || $length !== 0) {
                    return false;
                }
                break;
            case ASN1::TYPE_SEQUENCE:
            case ASN1::TYPE_SET:
                if (!$constructed) {
                    return false;
                }
                $offset = 0;
                while ($offset < $length) {
                    if (!$definite && $this->slice($contentBase + $offset, $contentEnd, 2) === "\0\0") {
                        $length = $offset + 2;
                        break 2;
                    }
                    $child = $this->decode($contentBase, $contentEnd, $offset, $depth + 1);
                    if ($child === false) {
                        return false;
                    }
                    $offset += $child[0];
                }
                break;
            case ASN1::TYPE_OBJECT_IDENTIFIER:
                if ($constructed) {
                    return false;
                }
                // The two cases in which decodeOID() gives up.
                if ($length > 128 || ($length > 0 && (\ord($this->der[$contentEnd - 1]) & 0x80) !== 0)) {
                    return false;
                }
                break;
            case ASN1::TYPE_NUMERIC_STRING:
            case ASN1::TYPE_PRINTABLE_STRING:
            case ASN1::TYPE_TELETEX_STRING:
            case ASN1::TYPE_VIDEOTEX_STRING:
            case ASN1::TYPE_VISIBLE_STRING:
            case ASN1::TYPE_IA5_STRING:
            case ASN1::TYPE_GRAPHIC_STRING:
            case ASN1::TYPE_GENERAL_STRING:
            case ASN1::TYPE_UTF8_STRING:
            case ASN1::TYPE_BMP_STRING:
            case ASN1::TYPE_UTC_TIME:
            case ASN1::TYPE_GENERALIZED_TIME:
                if ($constructed) {
                    return false;
                }
                break;
            default:
                return false;
        }

        return [$consumed + $length, $tag];
    }

    /**
     * Contents that phpseclib decodes again later, walked as DER of their own
     * and counted on top of the levels that enclose them.
     */
    private function walkContent(int $from, int $end, int $depth): void
    {
        if ($this->walkContents && $end - $from >= 2) {
            $this->decode($from, $end, 0, $depth + 1);
        }
    }

    /**
     * Up to $count octets from $from without passing $end, as substr() on the
     * enclosing content gives them to decode_ber().
     */
    private function slice(int $from, int $end, int $count): string
    {
        return $from >= $end ? '' : substr($this->der, $from, min($count, $end - $from));
    }
}
