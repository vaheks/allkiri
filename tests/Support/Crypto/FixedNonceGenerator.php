<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Crypto;

use Allkiri\Crypto\NonceGenerator;

/**
 * Deterministic nonces derived from a seed and a call counter, so that a
 * whole signing run produces byte-identical output across test runs.
 */
final class FixedNonceGenerator implements NonceGenerator
{
    private int $counter = 0;

    public function __construct(private readonly string $seed = 'allkiri-test') {}

    public function generate(int $bytes): string
    {
        $out = '';
        $block = 0;
        while (\strlen($out) < $bytes) {
            $out .= hash('sha256', $this->seed . ':' . $this->counter . ':' . $block, true);
            ++$block;
        }
        ++$this->counter;

        $nonce = substr($out, 0, $bytes);
        \assert($nonce !== '');

        return $nonce;
    }
}
