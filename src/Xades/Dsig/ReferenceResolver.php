<?php

declare(strict_types=1);

namespace Allkiri\Xades\Dsig;

/**
 * Supplies the bytes a ds:Reference with an external URI points at: the data
 * files of a container, or nothing for a signature whose references are all
 * same-document.
 */
interface ReferenceResolver
{
    /**
     * @param string $uri the reference URI, percent-decoded
     *
     * @return string|null the referenced bytes, or null when unknown
     */
    public function resolve(string $uri): ?string;
}
