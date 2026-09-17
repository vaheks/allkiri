<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Tsp;

/**
 * A token exists but does not prove what it claims.
 */
final class TimestampVerificationException extends TimestampException
{
    public const REASON_STRUCTURE = 'TIMESTAMP_STRUCTURE_INVALID';
    public const REASON_CONTENT_TYPE = 'TIMESTAMP_CONTENT_TYPE_INVALID';
    public const REASON_MESSAGE_DIGEST = 'TIMESTAMP_MESSAGE_DIGEST_MISMATCH';
    public const REASON_SIGNER_NOT_FOUND = 'TIMESTAMP_SIGNER_CERTIFICATE_NOT_FOUND';
    public const REASON_BAD_SIGNATURE = 'TIMESTAMP_SIGNATURE_INVALID';
    public const REASON_UNSUPPORTED_ALGORITHM = 'TIMESTAMP_SIGNATURE_ALGORITHM_UNSUPPORTED';

    /** The token verifies, but with SHA-1 or a key below the minimum. */
    public const REASON_ALGORITHM_NOT_ACCEPTED = 'TIMESTAMP_SIGNATURE_ALGORITHM_NOT_ACCEPTED';
    public const REASON_ESS_MISMATCH = 'TIMESTAMP_SIGNING_CERTIFICATE_REFERENCE_MISMATCH';
    public const REASON_TSA_KEY_USAGE = 'TIMESTAMP_TSA_KEY_USAGE_INVALID';
    public const REASON_IMPRINT = 'TIMESTAMP_MESSAGE_IMPRINT_MISMATCH';
    public const REASON_NONCE = 'TIMESTAMP_NONCE_MISMATCH';

    /** The token verifies, but its authority does not chain to a trusted timestamping service. */
    public const REASON_AUTHORITY_NOT_TRUSTED = 'TIMESTAMP_AUTHORITY_NOT_TRUSTED';
}
