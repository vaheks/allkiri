<?php

declare(strict_types=1);

namespace Allkiri\Xades\Dsig;

/**
 * The outcome for one ds:Reference.
 */
final readonly class ReferenceResult
{
    /**
     * @param list<string> $transforms transform algorithm URIs in order
     */
    public function __construct(
        public string $uri,
        public string $type,
        public string $id,
        public string $digestMethod,
        public array $transforms,
        public bool $resolved,
        public bool $digestMatches,
        public ?string $problem = null,
        /** More than one element carries the Id this reference names, so it was not followed. */
        public bool $ambiguous = false,
    ) {}

    public function isValid(): bool
    {
        return $this->resolved && $this->digestMatches;
    }

    public function isSameDocument(): bool
    {
        return $this->uri === '' || str_starts_with($this->uri, '#');
    }
}
