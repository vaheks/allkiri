<?php

declare(strict_types=1);

namespace Allkiri\Validation\Report;

/**
 * What one signature covers.
 */
final readonly class SignatureScope implements \JsonSerializable
{
    public function __construct(
        public string $name,
        public string $mimeType,
        public string $scope = 'FullSignatureScope',
        public string $content = 'Full document',
    ) {}

    /**
     * @return array<string, string>
     */
    public function jsonSerialize(): array
    {
        return ['name' => $this->name, 'scope' => $this->scope, 'content' => $this->content, 'mimeType' => $this->mimeType];
    }
}
