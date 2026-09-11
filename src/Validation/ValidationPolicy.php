<?php

declare(strict_types=1);

namespace Allkiri\Validation;

use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\SignatureAlgorithm;

/**
 * What a signature has to satisfy to be called valid.
 *
 * The defaults follow Estonian practice for BDOC 2.1.2 / ASiC-E: the
 * algorithms still considered sound, the DataObjectFormat the profile makes
 * mandatory, and the timestamp-to-OCSP window digidoc4j warns and fails on.
 */
final readonly class ValidationPolicy
{
    /**
     * @param list<HashAlgorithm>      $allowedDigestAlgorithms
     * @param list<SignatureAlgorithm> $allowedSignatureAlgorithms
     */
    public function __construct(
        public string $name = 'allkiri BDOC 2.1.2 / ASiC-E',
        public array $allowedDigestAlgorithms = [HashAlgorithm::SHA256, HashAlgorithm::SHA384, HashAlgorithm::SHA512],
        public ?array $allowedSignatureAlgorithms = null,
        public int $minimumRsaKeyBits = 2048,
        public bool $requireDataObjectFormat = true,
        public bool $requireSignedPropertiesReference = true,
        public int $ocspDelayWarningSeconds = 900,
        public int $ocspDelayErrorSeconds = 86400,
        public int $clockSkewSeconds = 300,
    ) {}

    public static function bdoc(): self
    {
        return new self();
    }

    public function allowsDigest(HashAlgorithm $algorithm): bool
    {
        return \in_array($algorithm, $this->allowedDigestAlgorithms, true);
    }

    public function allowsSignature(SignatureAlgorithm $algorithm): bool
    {
        if ($this->allowedSignatureAlgorithms !== null) {
            return \in_array($algorithm, $this->allowedSignatureAlgorithms, true);
        }

        return $this->allowsDigest($algorithm->hash());
    }
}
