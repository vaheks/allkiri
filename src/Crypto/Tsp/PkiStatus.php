<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Tsp;

/**
 * PKIStatus of a TimeStampResp (RFC 3161 §2.4.2).
 */
enum PkiStatus: int
{
    case Granted = 0;
    case GrantedWithMods = 1;
    case Rejection = 2;
    case Waiting = 3;
    case RevocationWarning = 4;
    case RevocationNotification = 5;

    public function isGranted(): bool
    {
        return $this === self::Granted || $this === self::GrantedWithMods;
    }
}
