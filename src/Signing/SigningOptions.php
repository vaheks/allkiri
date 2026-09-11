<?php

declare(strict_types=1);

namespace Allkiri\Signing;

use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Xades\SignatureProfile;

final readonly class SigningOptions
{
    /**
     * @param SignatureAlgorithm|null $signatureAlgorithm derived from the signer's key when null
     */
    public function __construct(
        public SignatureLevel $level = SignatureLevel::LT,
        public ?SignatureAlgorithm $signatureAlgorithm = null,
        public SignatureProfile $profile = new SignatureProfile(),
    ) {}

    public function withLevel(SignatureLevel $level): self
    {
        return new self($level, $this->signatureAlgorithm, $this->profile);
    }

    public function withAlgorithm(SignatureAlgorithm $algorithm): self
    {
        return new self($this->level, $algorithm, $this->profile);
    }

    public function withProfile(SignatureProfile $profile): self
    {
        return new self($this->level, $this->signatureAlgorithm, $profile);
    }
}
