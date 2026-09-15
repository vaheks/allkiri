<?php

declare(strict_types=1);

namespace Allkiri\Validation;

use Allkiri\Crypto\AlgorithmConstraints;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Exception\InvalidArgumentException;

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
     * @param bool                     $requireSignatureTimestamp  whether a signature without a signature timestamp can pass; without one only the signer's own claim says when it was made
     * @param int|null                 $trustedListGraceSeconds    how long after a trusted list's next update its anchors still count: null for always, with a warning; 0 to refuse them at once
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
        public bool $requireSignatureTimestamp = true,
        public ?int $trustedListGraceSeconds = null,
    ) {
        if ($trustedListGraceSeconds !== null && $trustedListGraceSeconds < 0) {
            throw new InvalidArgumentException('The trusted list grace period cannot be negative');
        }
    }

    public static function bdoc(): self
    {
        return new self();
    }

    public function allowsDigest(HashAlgorithm $algorithm): bool
    {
        return \in_array($algorithm, $this->allowedDigestAlgorithms, true);
    }

    /**
     * What the signatures a signature rests on must meet: those on its
     * certificates, its revocation answer and its timestamps. SHA-1 is refused
     * there whatever the policy allows for references, and the RSA key floor is
     * this policy's.
     */
    public function algorithmConstraints(): AlgorithmConstraints
    {
        return new AlgorithmConstraints($this->minimumRsaKeyBits);
    }

    public function allowsSignature(SignatureAlgorithm $algorithm): bool
    {
        if ($this->allowedSignatureAlgorithms !== null) {
            return \in_array($algorithm, $this->allowedSignatureAlgorithms, true);
        }

        return $this->allowsDigest($algorithm->hash());
    }
}
