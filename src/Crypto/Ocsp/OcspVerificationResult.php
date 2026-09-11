<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Ocsp;

use Allkiri\Crypto\Certificate;

/**
 * A verified OCSP answer about one certificate. Verified means: well-formed,
 * signed by an authorised responder, nonce and times acceptable. The status
 * itself may still be revoked or unknown; the caller decides what that means.
 */
final readonly class OcspVerificationResult
{
    /**
     * @param list<string> $warnings
     */
    public function __construct(
        public OcspResponse $response,
        public BasicOcspResponse $basic,
        public SingleResponse $single,
        public Certificate $responder,
        public bool $responderIsIssuer,
        public bool $responderFromTrustList,
        public array $warnings = [],
    ) {}

    public function status(): CertStatus
    {
        return $this->single->status;
    }

    public function producedAt(): \DateTimeImmutable
    {
        return $this->basic->producedAt();
    }
}
