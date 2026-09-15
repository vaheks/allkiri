<?php

declare(strict_types=1);

namespace Allkiri\Signing;

/**
 * What extending a signature to T or LT produced.
 */
final readonly class LtExtensionResult
{
    /**
     * @param list<string> $warnings
     */
    public function __construct(
        public SignatureLevel $level,
        public ?\DateTimeImmutable $timestampTime = null,
        public ?\DateTimeImmutable $ocspProducedAt = null,
        public array $warnings = [],
    ) {}
}
