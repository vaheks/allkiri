<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Ocsp;

/**
 * OCSPResponseStatus (RFC 6960 §4.2.1).
 */
enum OcspResponseStatus: string
{
    case Successful = 'successful';
    case MalformedRequest = 'malformedRequest';
    case InternalError = 'internalError';
    case TryLater = 'tryLater';
    case SigRequired = 'sigRequired';
    case Unauthorized = 'unauthorized';

    public function code(): int
    {
        return match ($this) {
            self::Successful => 0,
            self::MalformedRequest => 1,
            self::InternalError => 2,
            self::TryLater => 3,
            self::SigRequired => 5,
            self::Unauthorized => 6,
        };
    }
}
