<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Tsp;

use Allkiri\Crypto\CryptoException;

/**
 * Base of the timestamp layer's failures. `reason` is a stable machine-readable
 * code, one of the REASON_* constants here or in the subclasses.
 */
class TimestampException extends CryptoException
{
    /** The timestamp authority could not be reached. */
    public const REASON_TRANSPORT = 'TIMESTAMP_TRANSPORT';

    /** It answered with an HTTP error. */
    public const REASON_HTTP_STATUS = 'TIMESTAMP_HTTP_STATUS';

    /** The answer, or the token in it, could not be read. */
    public const REASON_MALFORMED_RESPONSE = 'TIMESTAMP_MALFORMED_RESPONSE';

    /** It refused the request, with the status and text it gave. */
    public const REASON_REJECTED = 'TIMESTAMP_REJECTED';

    public function __construct(
        public readonly string $reason,
        string $message,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
