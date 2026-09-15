<?php

declare(strict_types=1);

namespace Allkiri\Crypto;

use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\RSA;

/**
 * What the signatures a signature rests on must meet to be relied on: the
 * signatures on its certificates, on its revocation answer and on its
 * timestamps.
 *
 * Whether such a signature is genuine is checked elsewhere. This decides
 * whether a genuine one is still strong enough to count: SHA-1 is refused, and
 * so is an RSA key shorter than the minimum. The defaults apply wherever
 * allkiri signs or signs someone in; validation takes the minimum from its
 * policy.
 */
final readonly class AlgorithmConstraints
{
    public function __construct(public int $minimumRsaKeyBits = 2048) {}

    /**
     * Why a signature made with this algorithm and key cannot be relied on, or
     * null when it can. The reason reads after "is", as in "the OCSP response is
     * signed with SHA-1, which is no longer accepted".
     */
    public function violation(SignatureAlgorithmIdentifier $algorithm, PublicKey $signingKey): ?string
    {
        if ($algorithm->hash() === null) {
            return 'signed with SHA-1, which is no longer accepted';
        }
        if ($signingKey instanceof RSA\PublicKey) {
            $bits = Phpseclib::int($signingKey->getLength());
            if ($bits < $this->minimumRsaKeyBits) {
                return \sprintf('signed with a %d-bit RSA key, where at least %d bits are required', $bits, $this->minimumRsaKeyBits);
            }
        }

        return null;
    }
}
