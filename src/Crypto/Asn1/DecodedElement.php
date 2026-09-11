<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Asn1;

/**
 * The result of decoding DER against a map: the mapped value for convenient
 * access, and the raw node tree for exact byte slices.
 */
final class DecodedElement
{
    /**
     * @param array<string, mixed> $value
     */
    public function __construct(
        private readonly array $value,
        private readonly Node $node,
    ) {}

    /**
     * @return array<string, mixed> the phpseclib asn1map result
     */
    public function value(): array
    {
        return $this->value;
    }

    public function node(): Node
    {
        return $this->node;
    }

    public function der(): string
    {
        return $this->node->der();
    }

    /**
     * A mapped field by path, e.g. get('tbsResponseData', 'producedAt').
     */
    public function get(string ...$path): mixed
    {
        $current = $this->value;
        foreach ($path as $key) {
            if (!\is_array($current) || !\array_key_exists($key, $current)) {
                return null;
            }
            $current = $current[$key];
        }

        return $current;
    }

    public function string(string ...$path): string
    {
        $value = $this->get(...$path);
        if (!\is_string($value)) {
            throw new Asn1Exception(\sprintf('Field %s is not a string', implode('.', $path)));
        }

        return $value;
    }

    /**
     * @return array<mixed>
     */
    public function array(string ...$path): array
    {
        $value = $this->get(...$path);
        if (!\is_array($value)) {
            throw new Asn1Exception(\sprintf('Field %s is not an array', implode('.', $path)));
        }

        return $value;
    }

    public function has(string ...$path): bool
    {
        return $this->get(...$path) !== null;
    }
}
