<?php

declare(strict_types=1);

namespace Allkiri\Crypto;

/**
 * A private key with its certificate, as loaded from a PKCS#12 bundle or a
 * PEM pair.
 */
final readonly class KeyPair
{
    /**
     * @param list<Certificate> $chain issuer certificates shipped with the key, leaf's issuer first when known
     */
    public function __construct(
        public PrivateKey $privateKey,
        public Certificate $certificate,
        public array $chain = [],
    ) {}
}
