<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Ocsp;

use Allkiri\Crypto\Certificate;

final readonly class OcspVerificationOptions
{
    /**
     * @param list<Certificate> $trustedResponders responder certificates trusted
     *                                             outright (trusted-list OCSP/QC
     *                                             anchors), in addition to the
     *                                             issuing CA itself and delegated
     *                                             responders it has issued
     * @param int               $clockSkewSeconds  tolerance for thisUpdate / producedAt being slightly in the future
     * @param int|null          $maxAgeSeconds     when set, producedAt must not be older than this at the validation time (signing-time freshness)
     */
    public function __construct(
        public NonceMode $nonceMode = NonceMode::Required,
        public array $trustedResponders = [],
        public int $clockSkewSeconds = 300,
        public ?int $maxAgeSeconds = null,
    ) {}

    public static function forSigning(NonceMode $nonceMode = NonceMode::Required): self
    {
        return new self($nonceMode, [], 300, 600);
    }

    public static function forValidation(): self
    {
        return new self(NonceMode::Ignore, [], 300, null);
    }

    /**
     * @param list<Certificate> $trustedResponders
     */
    public function withTrustedResponders(array $trustedResponders): self
    {
        return new self($this->nonceMode, $trustedResponders, $this->clockSkewSeconds, $this->maxAgeSeconds);
    }
}
