<?php

declare(strict_types=1);

namespace Allkiri\Validation\Siva;

/**
 * SiVa's simple report, reduced to the parts worth comparing with our own.
 */
final readonly class SivaReport
{
    /**
     * @param list<SivaSignature> $signatures
     */
    public function __construct(
        public string $policy,
        public ?string $signatureForm,
        public int $signaturesCount,
        public int $validSignaturesCount,
        public array $signatures,
    ) {}

    public function isValid(): bool
    {
        return $this->signaturesCount > 0 && $this->validSignaturesCount === $this->signaturesCount;
    }

    /**
     * @param array<mixed> $data the decoded JSON body
     */
    public static function fromArray(array $data): self
    {
        $report = $data['validationReport'] ?? null;
        $conclusion = \is_array($report) ? ($report['validationConclusion'] ?? null) : null;
        if (!\is_array($conclusion)) {
            throw new SivaException(SivaException::REASON_MALFORMED, 'SiVa answered without a validation conclusion');
        }

        $signatures = [];
        foreach ((array) ($conclusion['signatures'] ?? []) as $signature) {
            if (\is_array($signature)) {
                $signatures[] = SivaSignature::fromArray($signature);
            }
        }
        $policy = $conclusion['policy'] ?? null;

        return new self(
            \is_array($policy) && \is_string($policy['policyName'] ?? null) ? $policy['policyName'] : 'unknown',
            \is_string($conclusion['signatureForm'] ?? null) ? $conclusion['signatureForm'] : null,
            self::count($conclusion, 'signaturesCount'),
            self::count($conclusion, 'validSignaturesCount'),
            $signatures,
        );
    }

    /**
     * @param array<mixed> $data
     */
    private static function count(array $data, string $key): int
    {
        $value = $data[$key] ?? null;

        return \is_int($value) ? $value : (is_numeric($value) ? (int) $value : 0);
    }

    /**
     * Everything SiVa complained about, across all signatures.
     *
     * @return list<string>
     */
    public function allErrors(): array
    {
        $errors = [];
        foreach ($this->signatures as $signature) {
            foreach ($signature->errors as $error) {
                $errors[] = $signature->id . ': ' . $error;
            }
        }

        return $errors;
    }
}
