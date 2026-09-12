<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

/**
 * How strong a certificate the request needs.
 *
 * `Qualified` and `Qscd` are both qualified; `Qscd` additionally requires the
 * key to live in a qualified signature creation device, which is what a
 * qualified electronic signature needs. The service answers a `Qscd` request
 * with a certificate reported as `QUALIFIED`, so the two are the same level
 * when the answer comes back.
 */
enum CertificateLevel: string
{
    case Advanced = 'ADVANCED';
    case Qualified = 'QUALIFIED';
    case Qscd = 'QSCD';

    /**
     * Whether a certificate at `$actual` satisfies a request for this level.
     */
    public function isSatisfiedBy(self $actual): bool
    {
        return $actual->weight() >= $this->weight();
    }

    private function weight(): int
    {
        return $this === self::Advanced ? 1 : 2;
    }
}
