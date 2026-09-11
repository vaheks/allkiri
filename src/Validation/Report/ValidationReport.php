<?php

declare(strict_types=1);

namespace Allkiri\Validation\Report;

/**
 * The verdict on a whole container.
 */
final readonly class ValidationReport implements \JsonSerializable
{
    /**
     * @param list<SignatureReport> $signatures
     * @param list<Finding>         $containerFindings problems with the container rather than a signature
     */
    public function __construct(
        public string $filename,
        public \DateTimeImmutable $validationTime,
        public string $policy,
        public array $signatures,
        public array $containerFindings = [],
    ) {}

    public function signaturesCount(): int
    {
        return \count($this->signatures);
    }

    public function validSignaturesCount(): int
    {
        return \count(array_filter($this->signatures, static fn(SignatureReport $s): bool => $s->isValid()));
    }

    /**
     * True when there is at least one signature and every one of them is valid.
     */
    public function isValid(): bool
    {
        return $this->signatures !== [] && $this->validSignaturesCount() === $this->signaturesCount();
    }

    public function signature(string $id): ?SignatureReport
    {
        foreach ($this->signatures as $signature) {
            if ($signature->id === $id) {
                return $signature;
            }
        }

        return null;
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return array_filter([
            'policy' => $this->policy,
            'validationTime' => $this->validationTime->format(DATE_ATOM),
            'validatedDocument' => ['filename' => $this->filename],
            'signaturesCount' => $this->signaturesCount(),
            'validSignaturesCount' => $this->validSignaturesCount(),
            'signatures' => $this->signatures,
            'containerErrors' => $this->containerFindings,
        ], static fn(mixed $value): bool => $value !== []);
    }
}
