<?php

declare(strict_types=1);

namespace Allkiri\Validation\Siva;

/**
 * One signature as SiVa reports it.
 */
final readonly class SivaSignature
{
    /**
     * @param list<string> $errors
     * @param list<string> $warnings
     */
    public function __construct(
        public string $id,
        public string $indication,
        public ?string $subIndication,
        public ?string $signatureFormat,
        public ?string $signatureLevel,
        public ?string $signedBy,
        public array $errors,
        public array $warnings,
        public ?string $claimedSigningTime = null,
        public ?string $timestampCreationTime = null,
        public ?string $ocspResponseCreationTime = null,
    ) {}

    public function isValid(): bool
    {
        return $this->indication === 'TOTAL-PASSED';
    }

    /**
     * @param array<mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $info = $data['info'] ?? null;
        $info = \is_array($info) ? $info : [];

        return new self(
            self::string($data, 'id') ?? '',
            self::string($data, 'indication') ?? 'INDETERMINATE',
            self::string($data, 'subIndication'),
            self::string($data, 'signatureFormat'),
            self::string($data, 'signatureLevel'),
            self::string($data, 'signedBy'),
            self::messages($data['errors'] ?? []),
            self::messages($data['warnings'] ?? []),
            self::string($data, 'claimedSigningTime'),
            self::string($info, 'timestampCreationTime'),
            self::string($info, 'ocspResponseCreationTime'),
        );
    }

    /**
     * @param array<mixed> $data
     */
    private static function string(array $data, string $key): ?string
    {
        $value = $data[$key] ?? null;

        return \is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * SiVa wraps each message in an object keyed "content".
     *
     * @return list<string>
     */
    private static function messages(mixed $entries): array
    {
        $messages = [];
        foreach ((array) $entries as $entry) {
            if (\is_array($entry) && \is_string($entry['content'] ?? null)) {
                $messages[] = $entry['content'];
            } elseif (\is_string($entry)) {
                $messages[] = $entry;
            }
        }

        return $messages;
    }
}
