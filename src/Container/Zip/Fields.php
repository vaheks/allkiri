<?php

declare(strict_types=1);

namespace Allkiri\Container\Zip;

use Allkiri\Container\InvalidContainerException;

/**
 * The integer fields of one ZIP header, unpacked once and read by name.
 *
 * ZIP headers are all little-endian unsigned integers, but unpack() is typed
 * as returning anything; this reads them once and hands out definite ints.
 */
final class Fields
{
    /** @var array<string, int> */
    private readonly array $values;

    /**
     * @param string $format an unpack() format of v (16-bit) and V (32-bit) fields only
     */
    public function __construct(string $format, string $bytes, string $what)
    {
        $unpacked = @unpack($format, $bytes);
        if ($unpacked === false) {
            throw new InvalidContainerException(\sprintf('Malformed %s', $what));
        }
        $values = [];
        foreach ($unpacked as $name => $value) {
            if (!\is_int($value)) {
                throw new InvalidContainerException(\sprintf('Malformed %s', $what));
            }
            $values[(string) $name] = $value;
        }
        $this->values = $values;
    }

    public function get(string $name): int
    {
        return $this->values[$name] ?? throw new InvalidContainerException(\sprintf('ZIP header has no field "%s"', $name));
    }

    /**
     * @return array<string, int>
     */
    public function all(): array
    {
        return $this->values;
    }
}
