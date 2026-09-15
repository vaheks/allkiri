<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Ocsp;

/**
 * The response exists but cannot be trusted or does not answer the question asked.
 */
final class OcspVerificationException extends OcspException
{
    public const REASON_STATUS = 'OCSP_STATUS_NOT_SUCCESSFUL';
    public const REASON_NOT_BASIC = 'OCSP_RESPONSE_TYPE_UNSUPPORTED';
    public const REASON_NO_MATCHING_RESPONSE = 'OCSP_NO_MATCHING_SINGLE_RESPONSE';
    public const REASON_RESPONDER_NOT_FOUND = 'OCSP_RESPONDER_CERTIFICATE_NOT_FOUND';
    public const REASON_BAD_SIGNATURE = 'OCSP_SIGNATURE_INVALID';
    public const REASON_UNSUPPORTED_ALGORITHM = 'OCSP_SIGNATURE_ALGORITHM_UNSUPPORTED';

    /** The response, or the delegated responder's certificate, verifies but with SHA-1 or a key below the minimum. */
    public const REASON_ALGORITHM_NOT_ACCEPTED = 'OCSP_SIGNATURE_ALGORITHM_NOT_ACCEPTED';
    public const REASON_RESPONDER_NOT_AUTHORISED = 'OCSP_RESPONDER_NOT_AUTHORISED';
    public const REASON_RESPONDER_CERTIFICATE_INVALID = 'OCSP_RESPONDER_CERTIFICATE_NOT_VALID';
    public const REASON_NONCE_MISMATCH = 'OCSP_NONCE_MISMATCH';
    public const REASON_NONCE_MISSING = 'OCSP_NONCE_MISSING';
    public const REASON_TIME = 'OCSP_TIME_OUT_OF_RANGE';
}
