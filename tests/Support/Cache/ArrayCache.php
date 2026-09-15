<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Cache;

use Psr\SimpleCache\CacheInterface;

/**
 * The smallest PSR-16 cache that works inside one process. Time to live is
 * accepted and ignored: tests control time with a frozen clock instead.
 */
final class ArrayCache implements CacheInterface
{
    /** @var array<string, mixed> */
    private array $values = [];

    /** How many times a value has been stored. */
    public int $writes = 0;

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->values[$key] ?? $default;
    }

    public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
    {
        $this->values[$key] = $value;
        ++$this->writes;

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->values[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->values = [];

        return true;
    }

    /**
     * @param iterable<mixed, string> $keys
     *
     * @return iterable<string, mixed>
     */
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $values = [];
        foreach ($keys as $key) {
            $values[$key] = $this->get($key, $default);
        }

        return $values;
    }

    /**
     * @param iterable<mixed, mixed> $values
     */
    public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set(\is_string($key) ? $key : (string) (\is_scalar($key) ? $key : ''), $value, $ttl);
        }

        return true;
    }

    /**
     * @param iterable<mixed, string> $keys
     */
    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        return isset($this->values[$key]);
    }
}
