<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\SmartId;

use Allkiri\Crypto\HashAlgorithm;
use Allkiri\SmartId\InteractionType;

/**
 * What the mock service remembers about a session it started.
 */
final class MockSession
{
    public int $polls = 0;

    public function __construct(
        public readonly string $type,
        public readonly string $challenge,
        public readonly HashAlgorithm $hashAlgorithm,
        public readonly string $interactions,
        public readonly string $relyingPartyName,
    ) {}

    /**
     * The dialogue the app would have shown: the first one offered.
     */
    public function firstInteraction(): InteractionType
    {
        $json = base64_decode($this->interactions, true);
        $decoded = $json === false ? null : json_decode($json, true);
        if (\is_array($decoded) && \is_array($decoded[0] ?? null) && \is_string($decoded[0]['type'] ?? null)) {
            return InteractionType::from($decoded[0]['type']);
        }

        return InteractionType::DisplayTextAndPin;
    }
}
