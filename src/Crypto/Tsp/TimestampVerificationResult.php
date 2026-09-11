<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Tsp;

use Allkiri\Crypto\Certificate;

/**
 * A structurally verified token: its signature checks out under the TSA
 * certificate and it covers the expected imprint. Whether that TSA is
 * trusted is the Trust layer's decision.
 */
final readonly class TimestampVerificationResult
{
    public function __construct(
        public TimestampToken $token,
        public Certificate $tsaCertificate,
    ) {}

    public function genTime(): \DateTimeImmutable
    {
        return $this->token->genTime();
    }
}
