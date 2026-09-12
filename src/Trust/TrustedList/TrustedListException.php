<?php

declare(strict_types=1);

namespace Allkiri\Trust\TrustedList;

use Allkiri\Trust\TrustException;

/**
 * A trusted list could not be fetched, parsed or trusted.
 */
final class TrustedListException extends TrustException
{
    public const REASON_TRANSPORT = 'TRUSTED_LIST_TRANSPORT';
    public const REASON_MALFORMED = 'TRUSTED_LIST_MALFORMED';
    public const REASON_SIGNATURE = 'TRUSTED_LIST_SIGNATURE_INVALID';
    public const REASON_SIGNER_NOT_ALLOWED = 'TRUSTED_LIST_SIGNER_NOT_ALLOWED';
    public const REASON_NO_PINS = 'TRUSTED_LIST_NO_ALLOWED_SIGNERS';

    /** The list of lists carries no usable list for a territory that was asked for. */
    public const REASON_NO_SUCH_LIST = 'TRUSTED_LIST_NOT_POINTED_TO';

    /** The lists loaded, but named nothing of the kind that was wanted. */
    public const REASON_NO_ANCHORS = 'TRUSTED_LIST_NO_ANCHORS';

    public function __construct(
        public readonly string $reason,
        string $message,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
