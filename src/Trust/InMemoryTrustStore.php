<?php

declare(strict_types=1);

namespace Allkiri\Trust;

use Allkiri\Crypto\Certificate;

final class InMemoryTrustStore implements TrustStore
{
    /** @var list<TrustAnchor> */
    private readonly array $anchors;

    /**
     * @param list<TrustAnchor> $anchors
     */
    public function __construct(array $anchors)
    {
        $this->anchors = array_values($anchors);
    }

    /**
     * @param list<Certificate> $certificates all trusted for the same service type, granted since forever
     */
    public static function fromCertificates(array $certificates, ServiceType $serviceType, string $source = 'manual'): self
    {
        return new self(array_map(static fn(Certificate $c): TrustAnchor => TrustAnchor::manual($c, $serviceType, '', $source), $certificates));
    }

    public function anchors(?array $types = null): array
    {
        if ($types === null) {
            return $this->anchors;
        }

        return array_values(array_filter($this->anchors, static fn(TrustAnchor $a): bool => \in_array($a->serviceType, $types, true)));
    }

    public function findAnchor(Certificate $certificate): ?TrustAnchor
    {
        foreach ($this->anchors as $anchor) {
            if ($anchor->certificate->equals($certificate)) {
                return $anchor;
            }
        }

        return null;
    }

    public function findIssuerAnchors(Certificate $subject): array
    {
        return array_values(array_filter($this->anchors, static fn(TrustAnchor $a): bool => self::couldHaveIssued($a->certificate, $subject)));
    }

    /**
     * Name match plus key-identifier match when both certificates carry identifiers.
     */
    public static function couldHaveIssued(Certificate $issuer, Certificate $subject): bool
    {
        if ($issuer->subjectNameDer() !== $subject->issuerNameDer()) {
            return false;
        }
        $aki = $subject->authorityKeyIdentifier();
        $ski = $issuer->subjectKeyIdentifier();

        return $aki === null || $ski === null || $aki === $ski;
    }
}
