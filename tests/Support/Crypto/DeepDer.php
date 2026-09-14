<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Crypto;

use Allkiri\Crypto\Certificate;
use phpseclib3\File\ASN1;

/**
 * DER nested far deeper than any real structure, on its own or hidden where
 * phpseclib decodes it a second time.
 */
final class DeepDer
{
    private function __construct() {}

    /**
     * A NULL inside this many SEQUENCEs, so one level more than $levels.
     */
    public static function nested(int $levels): string
    {
        $der = "\x05\x00";
        for ($i = 0; $i < $levels; ++$i) {
            $der = "\x30" . ASN1::encodeLength(\strlen($der)) . $der;
        }

        return $der;
    }

    /**
     * The certificate with $der as its basicConstraints value. The certificate
     * itself stays a few levels deep, and phpseclib decodes the extension value
     * separately while loading it.
     */
    public static function inBasicConstraints(Certificate $certificate, string $der): string
    {
        return self::replaceChild(
            $certificate->der(),
            static function (array $node): ?int {
                $children = self::children($node);
                $last = \count($children) - 1;

                return $last >= 1
                    && ($children[0]['type'] ?? null) === ASN1::TYPE_OBJECT_IDENTIFIER
                    && ($children[0]['content'] ?? null) === '2.5.29.19'
                    ? $last
                    : null;
            },
            "\x04" . ASN1::encodeLength(\strlen($der)) . $der,
        );
    }

    /**
     * The certificate with $der as its public key, which phpseclib decodes when
     * the key is first used.
     */
    public static function inPublicKey(Certificate $certificate, string $der): string
    {
        $bits = "\x00" . $der;

        return self::replaceChild(
            $certificate->der(),
            static function (array $node): ?int {
                $children = self::children($node);

                return \count($children) === 2
                    && ($children[0]['type'] ?? null) === ASN1::TYPE_SEQUENCE
                    && ($children[1]['type'] ?? null) === ASN1::TYPE_BIT_STRING
                    ? 1
                    : null;
            },
            "\x03" . ASN1::encodeLength(\strlen($bits)) . $bits,
        );
    }

    /**
     * @param \Closure(array<string, mixed>): ?int $select which child of a node to replace, if any
     */
    private static function replaceChild(string $der, \Closure $select, string $replacement): string
    {
        $root = ASN1::decodeBER($der)[0] ?? null;
        if (!\is_array($root)) {
            throw new \LogicException('Not DER');
        }
        /** @var array<string, mixed> $root */

        return self::rebuild($der, $root, $select, $replacement) ?? throw new \LogicException('Nothing to replace');
    }

    /**
     * The node re-encoded with the selected descendant replaced, or null when
     * nothing below it was selected.
     *
     * @param array<string, mixed>                  $node
     * @param \Closure(array<string, mixed>): ?int $select
     */
    private static function rebuild(string $der, array $node, \Closure $select, string $replacement): ?string
    {
        $children = self::children($node);
        if ($children === []) {
            return null;
        }
        $selected = $select($node);
        $replaced = false;
        $content = '';
        foreach ($children as $index => $child) {
            $part = null;
            if ($index === $selected) {
                $part = $replacement;
            } elseif (!$replaced) {
                $part = self::rebuild($der, $child, $select, $replacement);
            }
            if ($part === null) {
                $part = substr($der, self::int($child, 'start'), self::int($child, 'length'));
            } else {
                $replaced = true;
            }
            $content .= $part;
        }

        return $replaced ? $der[self::int($node, 'start')] . ASN1::encodeLength(\strlen($content)) . $content : null;
    }

    /**
     * @param array<string, mixed> $node
     *
     * @return list<array<string, mixed>>
     */
    private static function children(array $node): array
    {
        $content = $node['content'] ?? null;
        if (!\is_array($content)) {
            return [];
        }
        $children = [];
        foreach ($content as $child) {
            if (\is_array($child)) {
                /** @var array<string, mixed> $child */
                $children[] = $child;
            }
        }

        return $children;
    }

    /**
     * @param array<string, mixed> $node
     */
    private static function int(array $node, string $key): int
    {
        $value = $node[$key] ?? null;
        if (!\is_int($value)) {
            throw new \LogicException(\sprintf('Decoded node has no integer "%s"', $key));
        }

        return $value;
    }
}
