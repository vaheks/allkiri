<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Tsp;

use Allkiri\Crypto\CryptoException;

/**
 * Base of the timestamp layer's failures, with a stable machine-readable reason.
 */
class TimestampException extends CryptoException
{
    public function __construct(
        public readonly string $reason,
        string $message,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
