<?php

declare(strict_types=1);

namespace Allkiri\Signing;

use Allkiri\Container\AsicContainer;
use Allkiri\Xml\Dsig\ReferenceResolver;

/**
 * Resolves a signature's external references to the container's data files.
 */
final class ContainerReferenceResolver implements ReferenceResolver
{
    public function __construct(private readonly AsicContainer $container) {}

    public function resolve(string $uri): ?string
    {
        return $this->container->dataFile($uri)?->content;
    }
}
