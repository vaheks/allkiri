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

    /** A certificate is signed with an algorithm allkiri cannot verify. */
    public const REASON_UNSUPPORTED_ALGORITHM = 'CERTIFICATE_SIGNATURE_ALGORITHM_UNSUPPORTED';

    /** A certificate's signature verifies, but with SHA-1 or a key below the minimum. */
    public const REASON_ALGORITHM_NOT_ACCEPTED = 'CERTIFICATE_SIGNATURE_ALGORITHM_NOT_ACCEPTED';

    public function __construct(
        public readonly string $reason,
        string $message,
    ) {
        parent::__construct($message);
    }
}
