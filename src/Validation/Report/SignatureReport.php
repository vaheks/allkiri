<?php

declare(strict_types=1);

namespace Allkiri\Validation\Report;

use Allkiri\Crypto\Certificate;
use Allkiri\Signing\SignatureLevel;

/**
 * The verdict on one signature and everything behind it.
 */
final readonly class SignatureReport implements \JsonSerializable
{
    /**
     * @param list<Finding>        $findings all of them, in the order they were made
     * @param list<SignatureScope> $scopes
     */
    public function __construct(
        public string $id,
        public string $signatureFileName,
        public Indication $indication,
        public ?SubIndication $subIndication,
        public ?SignatureLevel $format,
        public string $signatureMethod,
        public array $findings,
        public SignatureInfo $info,
        public array $scopes = [],
        public ?Certificate $signingCertificate = null,
    ) {}

    public function isValid(): bool
    {
        return $this->indication === Indication::TotalPassed;
    }

    /**
     * The signer's common name, as reports show it.
     */
    public function signedBy(): ?string
    {
        return $this->signingCertificate?->commonName();
    }

    /**
     * @return list<Finding>
     */
    public function errors(): array
    {
        return $this->withSeverity(Severity::Error);
    }

    /**
     * @return list<Finding>
     */
    public function warnings(): array
    {
        return $this->withSeverity(Severity::Warning);
    }

    /**
     * @return list<string>
     */
    public function codes(): array
    {
        return array_map(static fn(Finding $f): string => $f->code, $this->findings);
    }

    public function has(string $code): bool
    {
        return \in_array($code, $this->codes(), true);
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return array_filter([
            'id' => $this->id,
            'signatureFileName' => $this->signatureFileName,
            'indication' => $this->indication->value,
            'subIndication' => $this->subIndication?->value,
            'signatureFormat' => $this->format?->value,
            'signatureMethod' => $this->signatureMethod,
            'signedBy' => $this->signedBy(),
            'subjectDistinguishedName' => $this->subjectDistinguishedName(),
            'errors' => $this->errors(),
            'warnings' => $this->warnings(),
            'info' => $this->info,
            'signatureScopes' => $this->scopes,
        ], static fn(mixed $value): bool => $value !== null && $value !== []);
    }

    /**
     * @return array<string, string>|null
     */
    private function subjectDistinguishedName(): ?array
    {
        $certificate = $this->signingCertificate;
        if ($certificate === null) {
            return null;
        }

        return array_filter([
            'commonName' => $certificate->commonName(),
            'serialNumber' => $certificate->subjectAttribute('serialNumber'),
            'givenName' => $certificate->subjectAttribute('GN'),
            'surname' => $certificate->subjectAttribute('SN'),
            'countryName' => $certificate->subjectAttribute('C'),
        ], static fn(?string $value): bool => $value !== null);
    }

    /**
     * @return list<Finding>
     */
    private function withSeverity(Severity $severity): array
    {
        return array_values(array_filter($this->findings, static fn(Finding $f): bool => $f->severity === $severity));
    }
}
