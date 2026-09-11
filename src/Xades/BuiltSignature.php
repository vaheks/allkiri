<?php

declare(strict_types=1);

namespace Allkiri\Xades;

use Allkiri\Crypto\HashAlgorithm;

/**
 * A XAdES-BES signature with everything but the SignatureValue: the document,
 * and the exact bytes the signer has to sign.
 */
final readonly class BuiltSignature
{
    public function __construct(
        public SignatureDocument $document,
        public string $signatureId,
        public string $signedInfoCanonical,
        public HashAlgorithm $digestAlgorithm,
    ) {}

    /**
     * The digest a remote signing service is asked to sign.
     */
    public function digest(): string
    {
        return $this->digestAlgorithm->digest($this->signedInfoCanonical);
    }
}
