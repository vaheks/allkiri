<?php

declare(strict_types=1);

namespace Allkiri\Validation\Report;

/**
 * Why a signature is not TOTAL-PASSED (ETSI EN 319 102-1 §5).
 */
enum SubIndication: string
{
    case FormatFailure = 'FORMAT_FAILURE';
    case HashFailure = 'HASH_FAILURE';
    case SigCryptoFailure = 'SIG_CRYPTO_FAILURE';
    case SignedDataNotFound = 'SIGNED_DATA_NOT_FOUND';
    case NoSigningCertificateFound = 'NO_SIGNING_CERTIFICATE_FOUND';
    case NoCertificateChainFound = 'NO_CERTIFICATE_CHAIN_FOUND';
    case CertificateChainGeneralFailure = 'CERTIFICATE_CHAIN_GENERAL_FAILURE';
    case CryptoConstraintsFailure = 'CRYPTO_CONSTRAINTS_FAILURE';

    /** An algorithm or key that is no longer acceptable, with no proof the signature existed while it still was. */
    case CryptoConstraintsFailureNoPoe = 'CRYPTO_CONSTRAINTS_FAILURE_NO_POE';
    case Expired = 'EXPIRED';
    case NotYetValid = 'NOT_YET_VALID';
    case OutOfBoundsNotRevoked = 'OUT_OF_BOUNDS_NOT_REVOKED';
    case Revoked = 'REVOKED';
    case TryLater = 'TRY_LATER';
    case NoPoe = 'NO_POE';
    case TimestampOrderFailure = 'TIMESTAMP_ORDER_FAILURE';
    case SigConstraintsFailure = 'SIG_CONSTRAINTS_FAILURE';
    case PolicyProcessingError = 'POLICY_PROCESSING_ERROR';
}
