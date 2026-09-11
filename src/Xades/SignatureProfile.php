<?php

declare(strict_types=1);

namespace Allkiri\Xades;

use Allkiri\Crypto\HashAlgorithm;

/**
 * The shape of the signatures allkiri produces.
 *
 * The defaults are what digidoc4j emits and what DigiDoc4 and SiVa expect;
 * change them only with a validator in hand.
 */
final readonly class SignatureProfile
{
    /**
     * @param string|null  $signatureId  a fixed signature Id, for reproducible output; generated when null
     * @param list<string> $claimedRoles roles the signer claims
     */
    public function __construct(
        public HashAlgorithm $digestAlgorithm = HashAlgorithm::SHA256,
        public string $canonicalizationMethod = Ns::C14N_EXC,
        public bool $useSigningCertificateV2 = true,
        public ?string $signatureId = null,
        public array $claimedRoles = [],
        public ?string $city = null,
        public ?string $stateOrProvince = null,
        public ?string $postalCode = null,
        public ?string $country = null,
    ) {}

    public function hasProductionPlace(): bool
    {
        return $this->city !== null || $this->stateOrProvince !== null || $this->postalCode !== null || $this->country !== null;
    }

    public function withSignatureId(string $signatureId): self
    {
        return new self(
            $this->digestAlgorithm,
            $this->canonicalizationMethod,
            $this->useSigningCertificateV2,
            $signatureId,
            $this->claimedRoles,
            $this->city,
            $this->stateOrProvince,
            $this->postalCode,
            $this->country,
        );
    }
}
