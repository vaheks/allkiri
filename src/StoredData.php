<?php

declare(strict_types=1);

namespace Allkiri;

use Allkiri\Crypto\Certificate;
use Allkiri\Exception\InvalidArgumentException;

/**
 * Reads back what a session, a prepared signature or a challenge wrote with
 * `jsonSerialize()`, so that every restore refuses the same things the same way.
 *
 * Stored data can carry a Smart-ID session secret, a phone number and an
 * identity code. It enters only through {@see restore()} and {@see decode()},
 * whose parameters are kept out of stack traces, and the readers keep it as a
 * property instead of passing it on. Messages name what was being read and
 * which field, never a stored value.
 *
 * @internal
 */
final readonly class StoredData
{
    /**
     * @param array<mixed> $data
     */
    private function __construct(
        #[\SensitiveParameter]
        private array $data,
        private string $label,
        public int $version,
    ) {}

    /**
     * @template T of object
     *
     * @param array<mixed>        $data     what `jsonSerialize()` wrote
     * @param string              $label    what is being restored, as messages name it: "Mobile-ID session"
     * @param non-empty-list<int> $versions every version the caller still reads
     * @param \Closure(self): T   $restore  builds the object from the fields
     *
     * @return T
     */
    public static function restore(#[\SensitiveParameter] array $data, string $label, array $versions, \Closure $restore): object
    {
        $version = $data['version'] ?? null;
        if (!\is_int($version) || !\in_array($version, $versions, true)) {
            throw new InvalidArgumentException(\sprintf('Unsupported %s version %s', $label, \is_int($version) ? (string) $version : get_debug_type($version)));
        }

        return $restore(new self($data, $label, $version));
    }

    /**
     * @return array<mixed>
     */
    public static function decode(#[\SensitiveParameter] string $json, string $label): array
    {
        $data = json_decode($json, true);
        if (!\is_array($data)) {
            throw new InvalidArgumentException(\sprintf('%s JSON is not an object', $label));
        }

        return $data;
    }

    public function string(string $key): string
    {
        $value = $this->field($key);
        if (!\is_string($value) || $value === '') {
            throw $this->invalid($key, 'must be a non-empty string');
        }

        return $value;
    }

    /**
     * Null when the field is absent, null or empty.
     */
    public function optionalString(string $key): ?string
    {
        $value = $this->data[$key] ?? null;
        if ($value === null || $value === '') {
            return null;
        }
        if (!\is_string($value)) {
            throw $this->invalid($key, 'must be a string');
        }

        return $value;
    }

    /**
     * @param bool $allowEmpty whether an empty value was stored on purpose
     */
    public function base64(string $key, bool $allowEmpty = false): string
    {
        $value = $this->field($key);
        $decoded = \is_string($value) ? base64_decode($value, true) : false;
        if ($decoded === false || (!$allowEmpty && $decoded === '')) {
            throw $this->invalid($key, 'is not base64');
        }

        return $decoded;
    }

    /**
     * @template E of \BackedEnum
     *
     * @param class-string<E> $enum
     *
     * @return E
     */
    public function enum(string $key, string $enum): \BackedEnum
    {
        return $enum::tryFrom($this->string($key)) ?? throw $this->invalid($key, 'has an unknown value');
    }

    /**
     * @template E of \BackedEnum
     *
     * @param class-string<E> $enum
     *
     * @return E|null
     */
    public function optionalEnum(string $key, string $enum): ?\BackedEnum
    {
        $value = $this->optionalString($key);

        return $value === null ? null : ($enum::tryFrom($value) ?? throw $this->invalid($key, 'has an unknown value'));
    }

    public function date(string $key): \DateTimeImmutable
    {
        return $this->parseDate($key, $this->string($key));
    }

    public function optionalDate(string $key): ?\DateTimeImmutable
    {
        $value = $this->optionalString($key);

        return $value === null ? null : $this->parseDate($key, $value);
    }

    public function certificate(string $key): Certificate
    {
        return Certificate::fromBase64($this->string($key));
    }

    /**
     * @return array<mixed>
     */
    public function object(string $key): array
    {
        $value = $this->field($key);
        if (!\is_array($value)) {
            throw $this->invalid($key, 'is not an object');
        }

        return $value;
    }

    private function field(string $key): mixed
    {
        return $this->data[$key] ?? throw new InvalidArgumentException(\sprintf('%s is missing "%s"', $this->label, $key));
    }

    /**
     * Only the form `jsonSerialize()` writes. A looser parse would read a
     * relative date such as "now" as the moment of reading.
     */
    private function parseDate(string $key, string $value): \DateTimeImmutable
    {
        $date = \DateTimeImmutable::createFromFormat(DATE_ATOM, $value);
        if ($date === false || \DateTimeImmutable::getLastErrors() !== false) {
            throw $this->invalid($key, 'is not a date');
        }

        return $date;
    }

    private function invalid(string $key, string $problem): InvalidArgumentException
    {
        return new InvalidArgumentException(\sprintf('%s field "%s" %s', $this->label, $key, $problem));
    }
}
