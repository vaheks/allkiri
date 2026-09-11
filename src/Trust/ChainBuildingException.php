<?php

declare(strict_types=1);

namespace Allkiri\Trust;

/**
 * No acceptable path from a certificate to a trust anchor. `reason` is a
 * stable code the validator maps onto its sub-indications.
 */
final class ChainBuildingException extends TrustException
{
    public const REASON_NOT_VALID_AT_TIME = 'CERTIFICATE_NOT_VALID_AT_TIME';
    public const REASON_NO_ISSUER = 'NO_ISSUER_FOUND';
    public const REASON_SIGNATURE = 'CERTIFICATE_SIGNATURE_INVALID';
    public const REASON_ANCHOR_NOT_VALID_AT_TIME = 'TRUST_ANCHOR_NOT_VALID_AT_TIME';
    public const REASON_ANCHOR_STATUS = 'TRUST_ANCHOR_STATUS_NOT_TRUSTWORTHY';
    public const REASON_ANCHOR_TYPE = 'TRUST_ANCHOR_SERVICE_TYPE_MISMATCH';
    public const REASON_DEPTH = 'CHAIN_TOO_LONG';

    public function __construct(
        public readonly string $reason,
        string $message,
    ) {
        parent::__construct($message);
    }
}
