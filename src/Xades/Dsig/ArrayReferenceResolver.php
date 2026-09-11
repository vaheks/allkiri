<?php

declare(strict_types=1);

namespace Allkiri\Xades\Dsig;

final class ArrayReferenceResolver implements ReferenceResolver
{
    /**
     * @param array<string, string> $contents name => bytes
     */
    public function __construct(private readonly array $contents = []) {}

    public function resolve(string $uri): ?string
    {
        return $this->contents[$uri] ?? null;
    }
}
