<?php

declare(strict_types=1);

namespace Allkiri\Crypto;

/**
 * Source of the nonces sent to OCSP responders, timestamp authorities and
 * authentication services. Injected so tests can replay byte-identical runs.
 */
interface NonceGenerator
{
    /**
     * @param int<1, max> $bytes
     *
     * @return non-empty-string exactly $bytes bytes
     */
    public function generate(int $bytes): string;
}
