<?php

declare(strict_types=1);

namespace Allkiri\Validation\Report;

/**
 * The times and attributes a report shows next to a signature, matching the
 * fields SiVa's simple report carries.
 */
final readonly class SignatureInfo implements \JsonSerializable
{
    /**
     * @param list<string> $signerRoles
     */
    public function __construct(
        public ?\DateTimeImmutable $claimedSigningTime = null,
        public ?\DateTimeImmutable $bestSignatureTime = null,
        public ?\DateTimeImmutable $timestampCreationTime = null,
        public ?\DateTimeImmutable $ocspResponseCreationTime = null,
        public ?string $timeAssertionMessageImprint = null,
        public array $signerRoles = [],
        public ?string $signatureProductionPlace = null,
        public ?\DateTimeImmutable $archiveTimestampTime = null,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return array_filter([
            'claimedSigningTime' => $this->claimedSigningTime?->format(DATE_ATOM),
            'bestSignatureTime' => $this->bestSignatureTime?->format(DATE_ATOM),
            'timestampCreationTime' => $this->timestampCreationTime?->format(DATE_ATOM),
            'ocspResponseCreationTime' => $this->ocspResponseCreationTime?->format(DATE_ATOM),
            'timeAssertionMessageImprint' => $this->timeAssertionMessageImprint,
            'signerRoles' => $this->signerRoles === [] ? null : $this->signerRoles,
            'signatureProductionPlace' => $this->signatureProductionPlace,
            'archiveTimestampTime' => $this->archiveTimestampTime?->format(DATE_ATOM),
        ], static fn(mixed $value): bool => $value !== null);
    }
}
