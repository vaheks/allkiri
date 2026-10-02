<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Ocsp;

use Allkiri\Crypto\CryptoException;

/**
 * Base of the OCSP layer's failures. `reason` is a stable machine-readable
 * code, one of the REASON_* constants here or in the subclasses, for an
 * application or a validator to branch on.
 */
class OcspException extends CryptoException
{
    /** The responder could not be reached. */
    public const REASON_TRANSPORT = 'OCSP_TRANSPORT';

    /** The responder answered with an HTTP error. */
    public const REASON_HTTP_STATUS = 'OCSP_HTTP_STATUS';

    /** The answer was not an OCSP response. */
    public const REASON_MALFORMED_RESPONSE = 'OCSP_MALFORMED_RESPONSE';

    /** Neither the certificate nor the configuration names a responder. */
    public const REASON_NO_RESPONDER_URL = 'OCSP_NO_RESPONDER_URL';

    public function __construct(
        public readonly string $reason,
        string $message,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
