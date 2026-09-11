<?php

declare(strict_types=1);

namespace Allkiri\Trust\TrustedList;

use Allkiri\Crypto\Certificate;
use Allkiri\Trust\ServiceType;

/**
 * Where a trusted list lives and who may sign it.
 *
 * The allowed signers are the trust decision: a list is only as trustworthy
 * as the certificates configured here. Production deployments pin the
 * certificates the EU list of trusted lists names for the territory; the
 * Estonian test list is pinned to its published signer.
 */
final readonly class TrustedListSource
{
    /**
     * @param list<Certificate>      $allowedSigners
     * @param list<ServiceType>|null $serviceTypes restrict which services become anchors; null for all supported
     */
    public function __construct(
        public string $url,
        public array $allowedSigners,
        public ?array $serviceTypes = null,
        public string $name = '',
        public int $cacheTtlSeconds = 86400,
    ) {}

    public function label(): string
    {
        return $this->name !== '' ? $this->name : $this->url;
    }

    public function cacheKey(): string
    {
        return 'allkiri.tsl.' . hash('sha256', $this->url);
    }
}
