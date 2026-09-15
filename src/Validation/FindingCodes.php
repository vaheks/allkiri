<?php

declare(strict_types=1);

namespace Allkiri\Validation;

/**
 * Every code the validator can report. These are the stable API: messages
 * may be reworded, codes may not.
 */
final class FindingCodes
{
    // Container structure
    public const NOT_A_CONTAINER = 'NOT_A_CONTAINER';
    public const MIMETYPE_INVALID = 'MIMETYPE_INVALID';
    public const MANIFEST_MISMATCH = 'MANIFEST_MISMATCH';
    public const NO_SIGNATURES = 'NO_SIGNATURES';
    public const SIGNATURE_FILE_MALFORMED = 'SIGNATURE_FILE_MALFORMED';

    // Signature structure
    public const SIGNATURE_MALFORMED = 'SIGNATURE_MALFORMED';
    public const SIGNED_PROPERTIES_REFERENCE_MISSING = 'SIGNED_PROPERTIES_REFERENCE_MISSING';
    public const UNSUPPORTED_BDOC_TM = 'UNSUPPORTED_BDOC_TM';
    public const MISSING_DATA_OBJECT_FORMAT = 'MISSING_DATA_OBJECT_FORMAT';
    public const MIME_TYPE_MISMATCH = 'MIME_TYPE_MISMATCH';
    /** An archive timestamp is there but does not hold up. */
    public const ARCHIVE_TIMESTAMP_INVALID = 'ARCHIVE_TIMESTAMP_INVALID';

    /** Its timestamp authority does not chain to a trusted one. */
    public const ARCHIVE_TIMESTAMP_NOT_TRUSTED = 'ARCHIVE_TIMESTAMP_NOT_TRUSTED';

    /** It is dated before something it covers. */
    public const ARCHIVE_TIMESTAMP_ORDER = 'ARCHIVE_TIMESTAMP_ORDER';

    /** Its token, or its authority's certificate, is signed with SHA-1 or a key below the minimum. */
    public const ARCHIVE_TIMESTAMP_WEAK_ALGORITHM = 'ARCHIVE_TIMESTAMP_WEAK_ALGORITHM';
    public const CRL_NOT_SUPPORTED = 'CRL_NOT_SUPPORTED';

    // Cryptography
    public const WEAK_DIGEST_ALGORITHM = 'WEAK_DIGEST_ALGORITHM';
    public const WEAK_SIGNATURE_ALGORITHM = 'WEAK_SIGNATURE_ALGORITHM';
    public const WEAK_KEY = 'WEAK_KEY';
    public const UNSUPPORTED_CANONICALIZATION = 'UNSUPPORTED_CANONICALIZATION';
    public const SIGNATURE_INVALID = 'SIGNATURE_INVALID';

    // References
    public const DATA_FILE_DIGEST_MISMATCH = 'DATA_FILE_DIGEST_MISMATCH';
    public const SIGNED_PROPERTIES_DIGEST_MISMATCH = 'SIGNED_PROPERTIES_DIGEST_MISMATCH';
    public const SIGNED_DATA_MISSING = 'SIGNED_DATA_MISSING';
    public const UNSIGNED_DATA_FILE = 'UNSIGNED_DATA_FILE';

    /** A reference names an Id that more than one element carries, so what it covers is ambiguous. */
    public const DUPLICATE_ID = 'DUPLICATE_ID';

    // Signing certificate
    public const SIGNING_CERTIFICATE_MISSING = 'SIGNING_CERTIFICATE_MISSING';
    public const SIGNING_CERTIFICATE_DIGEST_MISMATCH = 'SIGNING_CERTIFICATE_DIGEST_MISMATCH';
    public const ISSUER_SERIAL_MISMATCH = 'ISSUER_SERIAL_MISMATCH';
    public const SIGNING_CERTIFICATE_REFERENCE_MISSING = 'SIGNING_CERTIFICATE_REFERENCE_MISSING';

    /** The signing certificate's key usage does not include nonRepudiation, so it is not a certificate for signing. */
    public const SIGNING_CERTIFICATE_KEY_USAGE = 'SIGNING_CERTIFICATE_KEY_USAGE';

    // Timestamps
    public const TIMESTAMP_MISSING = 'TIMESTAMP_MISSING';
    public const TIMESTAMP_INVALID = 'TIMESTAMP_INVALID';
    public const TIMESTAMP_NOT_TRUSTED = 'TIMESTAMP_NOT_TRUSTED';
    public const NO_POE_CLAIMED_TIME_USED = 'NO_POE_CLAIMED_TIME_USED';

    /** The timestamp, or its authority's certificate, is signed with SHA-1 or a key below the minimum. */
    public const TIMESTAMP_WEAK_ALGORITHM = 'TIMESTAMP_WEAK_ALGORITHM';

    // Chain and revocation
    public const CHAIN_NOT_FOUND = 'CHAIN_NOT_FOUND';
    public const CHAIN_INVALID = 'CHAIN_INVALID';

    /** A certificate in the signer's chain is signed with SHA-1 or a key below the minimum. */
    public const CHAIN_WEAK_ALGORITHM = 'CHAIN_WEAK_ALGORITHM';

    /** A CA in the signer's chain is outside its path length constraint, or may not sign certificates. */
    public const CHAIN_CONSTRAINT_VIOLATED = 'CHAIN_CONSTRAINT_VIOLATED';
    public const SIGNING_CERTIFICATE_EXPIRED = 'SIGNING_CERTIFICATE_EXPIRED';
    public const SIGNING_CERTIFICATE_NOT_YET_VALID = 'SIGNING_CERTIFICATE_NOT_YET_VALID';
    public const REVOCATION_MISSING = 'REVOCATION_MISSING';
    public const REVOCATION_INVALID = 'REVOCATION_INVALID';

    /** The only usable revocation answer, or its responder's certificate, is signed with SHA-1 or a key below the minimum. */
    public const REVOCATION_WEAK_ALGORITHM = 'REVOCATION_WEAK_ALGORITHM';
    public const CERTIFICATE_REVOKED = 'CERTIFICATE_REVOKED';
    public const CERTIFICATE_STATUS_UNKNOWN = 'CERTIFICATE_STATUS_UNKNOWN';
    public const OCSP_BEFORE_TIMESTAMP = 'OCSP_BEFORE_TIMESTAMP';
    public const OCSP_TIMESTAMP_DELTA_TOO_LARGE = 'OCSP_TIMESTAMP_DELTA_TOO_LARGE';
    public const OCSP_TIMESTAMP_DELTA_WARNING = 'OCSP_TIMESTAMP_DELTA_WARNING';

    private function __construct() {}
}
