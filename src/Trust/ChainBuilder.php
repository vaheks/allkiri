<?php

declare(strict_types=1);

namespace Allkiri\Trust;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\UnsupportedAlgorithmException;

/**
 * Finds a path from a certificate to a trust anchor that is valid at a given
 * moment: every certificate within its validity period, every signature
 * verified, the anchor's service in a trustworthy status at that moment.
 *
 * Intermediates come from the caller (a signature's KeyInfo and
 * CertificateValues, an OCSP response's certs, a timestamp token's
 * certificates); anchors come from the trust store.
 */
final class ChainBuilder
{
    private const MAX_DEPTH = 8;

    public function __construct(private readonly TrustStore $store) {}

    /**
     * @param list<Certificate>      $intermediates candidate issuer certificates that are not anchors
     * @param list<ServiceType>|null $acceptedAnchorTypes which service types may terminate the chain; null for any
     *
     * @throws ChainBuildingException when no acceptable chain exists (reason tells which condition failed closest to the leaf)
     */
    public function build(Certificate $leaf, array $intermediates, \DateTimeInterface $validationTime, ?array $acceptedAnchorTypes = null): CertificateChain
    {
        $failure = null;
        $chain = $this->search($leaf, $intermediates, $validationTime, $acceptedAnchorTypes, [], $failure);
        if ($chain !== null) {
            return $chain;
        }

        throw $failure ?? new ChainBuildingException(ChainBuildingException::REASON_NO_ISSUER, \sprintf('No issuer found for %s', $leaf->subjectDn()));
    }

    /**
     * @param list<Certificate>      $intermediates
     * @param list<ServiceType>|null $acceptedAnchorTypes
     * @param list<Certificate>      $path certificates below the current one, leaf first
     */
    private function search(Certificate $current, array $intermediates, \DateTimeInterface $time, ?array $acceptedAnchorTypes, array $path, ?ChainBuildingException &$failure): ?CertificateChain
    {
        if (\count($path) >= self::MAX_DEPTH) {
            $failure ??= new ChainBuildingException(ChainBuildingException::REASON_DEPTH, 'Certificate chain exceeds the maximum depth');

            return null;
        }
        if (!$current->isValidAt($time)) {
            $failure = new ChainBuildingException(ChainBuildingException::REASON_NOT_VALID_AT_TIME, \sprintf('%s is not valid at %s', $current->subjectDn(), $time->format(DATE_ATOM)));

            return null;
        }
        $path[] = $current;

        // The certificate itself may be an anchor (TSU and OCSP responder certificates listed directly in a trusted list).
        $direct = $this->store->findAnchor($current);
        if ($direct !== null) {
            $result = $this->acceptAnchor($direct, $path, $time, $acceptedAnchorTypes, $failure);
            if ($result !== null) {
                return $result;
            }
        }

        // Anchors that could have issued it.
        foreach ($this->store->findIssuerAnchors($current) as $anchor) {
            if (!$this->signedBy($current, $anchor->certificate, $failure)) {
                continue;
            }
            $result = $this->acceptAnchor($anchor, [...$path, $anchor->certificate], $time, $acceptedAnchorTypes, $failure);
            if ($result !== null) {
                return $result;
            }
        }

        // Intermediates that could have issued it.
        foreach ($intermediates as $candidate) {
            if ($candidate->equals($current) || !$candidate->isCa() || !InMemoryTrustStore::couldHaveIssued($candidate, $current)) {
                continue;
            }
            foreach ($path as $seen) {
                if ($seen->equals($candidate)) {
                    continue 2;
                }
            }
            if (!$this->signedBy($current, $candidate, $failure)) {
                continue;
            }
            $result = $this->search($candidate, $intermediates, $time, $acceptedAnchorTypes, $path, $failure);
            if ($result !== null) {
                return $result;
            }
        }

        $failure ??= new ChainBuildingException(ChainBuildingException::REASON_NO_ISSUER, \sprintf('No issuer found for %s', $current->subjectDn()));

        return null;
    }

    /**
     * @param non-empty-list<Certificate> $path
     * @param list<ServiceType>|null      $acceptedAnchorTypes
     */
    private function acceptAnchor(TrustAnchor $anchor, array $path, \DateTimeInterface $time, ?array $acceptedAnchorTypes, ?ChainBuildingException &$failure): ?CertificateChain
    {
        if ($acceptedAnchorTypes !== null && !\in_array($anchor->serviceType, $acceptedAnchorTypes, true)) {
            $failure = new ChainBuildingException(ChainBuildingException::REASON_ANCHOR_TYPE, \sprintf('Trust anchor "%s" is a %s service, not one of the accepted types', $anchor->serviceName, $anchor->serviceType->name));

            return null;
        }
        if (!$anchor->certificate->isValidAt($time)) {
            $failure = new ChainBuildingException(ChainBuildingException::REASON_ANCHOR_NOT_VALID_AT_TIME, \sprintf('Trust anchor "%s" is not valid at %s', $anchor->serviceName, $time->format(DATE_ATOM)));

            return null;
        }
        if (!$anchor->isTrustworthyAt($time)) {
            $status = $anchor->statusAt($time);
            $failure = new ChainBuildingException(ChainBuildingException::REASON_ANCHOR_STATUS, \sprintf('Trust anchor "%s" has status %s at %s', $anchor->serviceName, $status === null ? 'none' : $status->name, $time->format(DATE_ATOM)));

            return null;
        }

        return new CertificateChain($path, $anchor);
    }

    private function signedBy(Certificate $subject, Certificate $issuer, ?ChainBuildingException &$failure): bool
    {
        try {
            if ($subject->isSignedBy($issuer)) {
                return true;
            }
        } catch (UnsupportedAlgorithmException $e) {
            $failure = new ChainBuildingException(ChainBuildingException::REASON_SIGNATURE, $e->getMessage());

            return false;
        }
        $failure = new ChainBuildingException(ChainBuildingException::REASON_SIGNATURE, \sprintf('%s is not signed by %s', $subject->subjectDn(), $issuer->subjectDn()));

        return false;
    }
}
