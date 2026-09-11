<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Ocsp;

enum CertStatus: string
{
    case Good = 'good';
    case Revoked = 'revoked';
    case Unknown = 'unknown';
}
