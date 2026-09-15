<?php

declare(strict_types=1);

namespace Allkiri\Xml\Dsig;

use Allkiri\Crypto\Certificate;

/**
 * Core XML-DSig verification: reference digests and the SignatureValue.
 * Says nothing about trust, time or XAdES qualifying properties.
 */
final readonly class DsigVerificationResult
{
    /**
     * @param list<ReferenceResult> $references
     * @param list<string>          $problems structural problems found on the way
     */
    public function __construct(
        public array $references,
        public bool $signatureValid,
        public string $signatureMethod,
        public string $canonicalizationMethod,
        public ?Certificate $certificate,
        public string $signedInfoCanonical,
        public array $problems = [],
    ) {}

    public function isValid(): bool
    {
        if (!$this->signatureValid || $this->references === []) {
            return false;
        }
        foreach ($this->references as $reference) {
            if (!$reference->isValid()) {
                return false;
            }
        }

        return true;
    }

    public function reference(string $uri): ?ReferenceResult
    {
        foreach ($this->references as $reference) {
            if ($reference->uri === $uri) {
                return $reference;
            }
        }

        return null;
    }
}
