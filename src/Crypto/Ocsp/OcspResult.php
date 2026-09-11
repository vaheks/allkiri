<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Ocsp;

/**
 * What {@see OcspClient::fetch()} returns: the exact response bytes to embed
 * and the verification that vouches for them.
 */
final readonly class OcspResult
{
    public function __construct(
        public string $url,
        public OcspResponse $response,
        public OcspVerificationResult $verification,
    ) {}

    public function der(): string
    {
        return $this->response->der();
    }
}
