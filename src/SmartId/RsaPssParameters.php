<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\SignatureAlgorithm;

/**
 * The RSASSA-PSS parameters the service reports for a signature it produced.
 *
 * They are checked rather than trusted, because only one combination is usable
 * here: MGF1 over the same hash, a salt as long as the digest, and the 0xbc
 * trailer. That is the profile RFC 6931 fixes for the
 * `…xmldsig-more#sha256-rsa-MGF1` family of XML-DSig methods, so a signature
 * with any other parameters could not be described by the method a XAdES
 * signature declares, and would be rejected by every validator.
 */
final readonly class RsaPssParameters
{
    public const TRAILER_FIELD = '0xbc';

    public function __construct(
        public HashAlgorithm $hashAlgorithm,
        public HashAlgorithm $maskHashAlgorithm,
        public int $saltLength,
        public string $trailerField,
    ) {}

    /**
     * Whether these are the parameters RFC 6931's PSS methods describe.
     */
    public function isRfc6931Profile(): bool
    {
        return $this->maskHashAlgorithm === $this->hashAlgorithm
            && $this->saltLength === $this->hashAlgorithm->digestLength()
            && strtolower($this->trailerField) === self::TRAILER_FIELD;
    }

    /**
     * Why they are not, in a sentence fit for an exception.
     */
    public function complaint(): ?string
    {
        if ($this->maskHashAlgorithm !== $this->hashAlgorithm) {
            return \sprintf(
                'the mask generation function uses %s while the digest uses %s',
                $this->maskHashAlgorithm->name(true),
                $this->hashAlgorithm->name(true),
            );
        }
        if ($this->saltLength !== $this->hashAlgorithm->digestLength()) {
            return \sprintf(
                'the salt is %d bytes where %s requires %d',
                $this->saltLength,
                $this->hashAlgorithm->name(true),
                $this->hashAlgorithm->digestLength(),
            );
        }
        if (strtolower($this->trailerField) !== self::TRAILER_FIELD) {
            return \sprintf('the trailer field is %s rather than %s', $this->trailerField, self::TRAILER_FIELD);
        }

        return null;
    }

    /**
     * The XML-DSig signature method these parameters correspond to.
     */
    public function signatureAlgorithm(): SignatureAlgorithm
    {
        return match ($this->hashAlgorithm) {
            HashAlgorithm::SHA256 => SignatureAlgorithm::PS256,
            HashAlgorithm::SHA384 => SignatureAlgorithm::PS384,
            HashAlgorithm::SHA512 => SignatureAlgorithm::PS512,
        };
    }
}
