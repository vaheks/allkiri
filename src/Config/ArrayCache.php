<?php

declare(strict_types=1);

namespace Allkiri\Config;

use Psr\SimpleCache\CacheInterface;

/**
 * A cache that lives for one process, so a script that signs several documents
 * downloads the trusted list once.
 *
 * A real application should inject its own PSR-16 cache instead, or the list
 * is fetched again on every request.
 */
final class ArrayCache implements CacheInterface
{
    /** @var array<string, array{value: mixed, expiresAt: int|null}> */
    private array $entries = [];

    public function get(string $key, mixed $default = null): mixed
    {
        $entry = $this->entries[$key] ?? null;
        if ($entry === null) {
            return $default;
        }
        if ($entry['expiresAt'] !== null && $entry['expiresAt'] < time()) {
            unset($this->entries[$key]);

            return $default;
        }

        return $entry['value'];
    }

    public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
    {
        $this->entries[$key] = ['value' => $value, 'expiresAt' => self::expiry($ttl)];

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->entries[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->entries = [];

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
            if (\is_string($key)) {
                $this->set($key, $value, $ttl);
            }
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
        return $this->get($key, $this) !== $this;
    }

    private static function expiry(null|int|\DateInterval $ttl): ?int
    {
        if ($ttl === null) {
            return null;
        }
        if (\is_int($ttl)) {
            return time() + $ttl;
        }

        return (new \DateTimeImmutable())->add($ttl)->getTimestamp();
    }
}
