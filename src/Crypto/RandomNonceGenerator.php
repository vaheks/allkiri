<?php

declare(strict_types=1);

namespace Allkiri\Crypto;

final class RandomNonceGenerator implements NonceGenerator
{
    public function generate(int $bytes): string
    {
        return random_bytes($bytes);
    }
}
