<?php

declare(strict_types=1);

namespace Allkiri\Crypto;

use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;

enum KeyType
{
    case RSA;
    case EC;

    public static function of(PublicKey $key): self
    {
        return match (true) {
            $key instanceof RSA\PublicKey => self::RSA,
            $key instanceof EC\PublicKey => self::EC,
            default => throw new UnsupportedAlgorithmException(\sprintf('Unsupported public key type %s', $key::class)),
        };
    }
}
