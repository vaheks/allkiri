<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Ocsp;

use Allkiri\Crypto\CryptoException;

/**
 * Base of the OCSP layer's failures. `reason` is a stable machine-readable
 * code (see the REASON_* constants of the subclasses) for validators to map.
 */
class OcspException extends CryptoException
{
    public function __construct(
        public readonly string $reason,
        string $message,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
