<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Ocsp;

/**
 * A verified OCSP response says the certificate is revoked (or unknown to
 * the responder, which for signing is just as fatal).
 */
final class CertificateRevokedException extends OcspException
{
    public const REASON_REVOKED = 'CERTIFICATE_REVOKED';
    public const REASON_UNKNOWN = 'CERTIFICATE_STATUS_UNKNOWN';

    public function __construct(
        string $reason,
        string $message,
        public readonly ?\DateTimeImmutable $revokedAt = null,
        public readonly ?string $revocationReason = null,
    ) {
        parent::__construct($reason, $message);
    }
}
