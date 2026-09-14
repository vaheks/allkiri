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

    /**
     * The certificate policies SK puts in a Smart-ID authentication certificate
     * of this level: its own, and the ETSI one. QC statements do not tell the
     * levels apart, so these are what bear a reported level out.
     *
     * @see https://www.skidsolutions.eu/resources/profiles/ SK-CPR-SMART-ID, section 2.2.3
     *
     * @return list<string>
     */
    public function authenticationPolicies(): array
    {
        return $this === self::Advanced
            ? ['1.3.6.1.4.1.10015.17.1', '0.4.0.2042.1.1']
            : ['1.3.6.1.4.1.10015.17.2', '0.4.0.2042.1.2'];
    }

    private function weight(): int
    {
        return $this === self::Advanced ? 1 : 2;
    }
}
