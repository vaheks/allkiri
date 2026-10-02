<?php

declare(strict_types=1);

namespace Allkiri\Validation\Report;

/**
 * The verdict on a whole container.
 */
final readonly class ValidationReport implements \JsonSerializable
{
    /**
     * The shape of the JSON. A key may be added in a minor release; removing or
     * renaming one, or changing what it means, takes a new version.
     */
    public const VERSION = 1;

    /**
     * @param list<SignatureReport> $signatures
     * @param list<Finding>         $containerFindings problems with the container rather than a signature
     *
     * @internal the library builds these, so the parameters may change in a minor release
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
     * In the shape SiVa reports in, with a version. A list with nothing in it
     * and a value that is not known are left out, here and in each signature,
     * rather than written as [] or null.
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return array_filter([
            'version' => self::VERSION,
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
