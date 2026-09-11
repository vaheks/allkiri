<?php

declare(strict_types=1);

namespace Allkiri\Signing;

use Allkiri\Container\AsicContainer;

/**
 * A finished signature and the container that now carries it.
 */
final readonly class SigningResult
{
    /**
     * @param list<string> $warnings things worth telling the user about a signature that was still created
     */
    public function __construct(
        public AsicContainer $container,
        public string $signatureId,
        public string $signatureFileName,
        public SignatureLevel $level,
        public ?\DateTimeImmutable $timestampTime = null,
        public ?\DateTimeImmutable $ocspProducedAt = null,
        public array $warnings = [],
    ) {}
}
