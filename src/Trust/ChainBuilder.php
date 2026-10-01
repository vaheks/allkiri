<?php

declare(strict_types=1);

namespace Allkiri\Trust;

use Allkiri\Crypto\AlgorithmConstraints;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\CryptoException;

/**
 * Finds a path from a certificate to a trust anchor that is valid at a given
 * moment: every certificate within its validity period, every signature
 * verified and made with an acceptable algorithm and key, every CA within its
 * own constraints, the anchor's service in a trustworthy status at that moment.
 *
 * Intermediates come from the caller (a signature's KeyInfo and
 * CertificateValues, an OCSP response's certs, a timestamp token's
 * certificates); anchors come from the trust store.
 */
final class ChainBuilder
{
    private const MAX_DEPTH = 8;

    /**
     * The search is bounded, because the candidates are whatever the document
     * brought. A dozen CA certificates sharing one name and one key each verify
     * as the issuer of every other, and an unbounded search walks every
     * ordering of them: at eight that took nearly two minutes, and every one
     * more multiplies it. Real candidates number under ten, and a real chain is
     * found within a handful of steps and signature checks.
     */
    private const MAX_CANDIDATES = 32;
    private const MAX_STEPS = 256;
    private const MAX_SIGNATURE_CHECKS = 128;

    /**
     * How far along a path each failure got. When no path works, the failure
     * reported is the one that got furthest: a path that reached an anchor over
     * genuine signatures says more than a candidate that never signed the
     * certificate at all. Reasons not listed rank highest.
     */
    private const FAILURE_RANKS = [
        ChainBuildingException::REASON_NO_ISSUER => 0,
        ChainBuildingException::REASON_DEPTH => 1,
        ChainBuildingException::REASON_SIGNATURE => 2,
        ChainBuildingException::REASON_UNSUPPORTED_ALGORITHM => 3,
    ];

    /** Failures reached over a genuine signature: validity, the anchor, algorithm constraints. */
    private const RANK_PAST_A_SIGNATURE = 4;

    /**
     * What one build() has learnt: each issuer–subject pair's signature check,
     * keyed by both fingerprints, with the failure it recorded.
     *
     * @var array<string, array{bool, ?ChainBuildingException}>
     */
    private array $signatureChecks = [];

    private int $steps = 0;

    public function __construct(
        private readonly TrustStore $store,
        private readonly AlgorithmConstraints $constraints = new AlgorithmConstraints(),
    ) {}

    /**
     * @param list<Certificate>      $intermediates candidate issuer certificates that are not anchors
     * @param list<ServiceType>|null $acceptedAnchorTypes which service types may terminate the chain; null for any
     *
     * @throws ChainBuildingException when no acceptable chain exists; the reason is the failure that got furthest along a path,
     *                                or REASON_SEARCH_LIMIT when the candidates would take longer to search than any real chain does
     */
    public function build(Certificate $leaf, array $intermediates, \DateTimeInterface $validationTime, ?array $acceptedAnchorTypes = null): CertificateChain
    {
        $candidates = [];
        foreach ($intermediates as $intermediate) {
            $candidates[$intermediate->der()] = $intermediate;
        }
        if (\count($candidates) > self::MAX_CANDIDATES) {
            throw new ChainBuildingException(ChainBuildingException::REASON_SEARCH_LIMIT, \sprintf('%d candidate certificates were offered for the chain of %s; no more than %d are searched', \count($candidates), $leaf->subjectDn(), self::MAX_CANDIDATES));
        }

        $this->signatureChecks = [];
        $this->steps = 0;
        $failure = null;
        try {
            $chain = $this->search($leaf, array_values($candidates), $validationTime, $acceptedAnchorTypes, [], $failure);
        } finally {
            $this->signatureChecks = [];
        }
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
        if (++$this->steps > self::MAX_STEPS) {
            throw new ChainBuildingException(ChainBuildingException::REASON_SEARCH_LIMIT, \sprintf('The candidate certificates allow more paths than are searched, after %d steps', self::MAX_STEPS));
        }
        if (\count($path) >= self::MAX_DEPTH) {
            self::record($failure, new ChainBuildingException(ChainBuildingException::REASON_DEPTH, 'Certificate chain exceeds the maximum depth'));

            return null;
        }
        if (!$current->isValidAt($time)) {
            self::record($failure, new ChainBuildingException(ChainBuildingException::REASON_NOT_VALID_AT_TIME, \sprintf('%s is not valid at %s', $current->subjectDn(), $time->format(DATE_ATOM))));

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
            if (!$this->signedBy($current, $anchor->certificate, $failure) || !$this->mayIssue($anchor->certificate, $path, false, $failure)) {
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
            if (!$this->signedBy($current, $candidate, $failure) || !$this->mayIssue($candidate, $path, true, $failure)) {
                continue;
            }
            $result = $this->search($candidate, $intermediates, $time, $acceptedAnchorTypes, $path, $failure);
            if ($result !== null) {
                return $result;
            }
        }

        self::record($failure, new ChainBuildingException(ChainBuildingException::REASON_NO_ISSUER, \sprintf('No issuer found for %s', $current->subjectDn())));

        return null;
    }

    /**
     * @param non-empty-list<Certificate> $path
     * @param list<ServiceType>|null      $acceptedAnchorTypes
     */
    private function acceptAnchor(TrustAnchor $anchor, array $path, \DateTimeInterface $time, ?array $acceptedAnchorTypes, ?ChainBuildingException &$failure): ?CertificateChain
    {
        if ($acceptedAnchorTypes !== null && !\in_array($anchor->serviceType, $acceptedAnchorTypes, true)) {
            self::record($failure, new ChainBuildingException(ChainBuildingException::REASON_ANCHOR_TYPE, \sprintf('Trust anchor "%s" is a %s service, not one of the accepted types', $anchor->serviceName, $anchor->serviceType->name)));

            return null;
        }
        if (!$anchor->certificate->isValidAt($time)) {
            self::record($failure, new ChainBuildingException(ChainBuildingException::REASON_ANCHOR_NOT_VALID_AT_TIME, \sprintf('Trust anchor "%s" is not valid at %s', $anchor->serviceName, $time->format(DATE_ATOM))));

            return null;
        }
        if (!$anchor->isTrustworthyAt($time)) {
            $status = $anchor->statusAt($time);
            self::record($failure, new ChainBuildingException(ChainBuildingException::REASON_ANCHOR_STATUS, \sprintf('Trust anchor "%s" has status %s at %s', $anchor->serviceName, $status === null ? 'none' : $status->name, $time->format(DATE_ATOM))));

            return null;
        }

        return new CertificateChain($path, $anchor);
    }

    /**
     * Whether the issuer signed the subject with an algorithm and key that are
     * still acceptable.
     */
    private function signedBy(Certificate $subject, Certificate $issuer, ?ChainBuildingException &$failure): bool
    {
        $pair = $issuer->fingerprint() . $subject->fingerprint();
        if (!isset($this->signatureChecks[$pair])) {
            if (\count($this->signatureChecks) >= self::MAX_SIGNATURE_CHECKS) {
                throw new ChainBuildingException(ChainBuildingException::REASON_SEARCH_LIMIT, \sprintf('The candidate certificates need more than %d signature checks', self::MAX_SIGNATURE_CHECKS));
            }
            $this->signatureChecks[$pair] = $this->checkSignature($subject, $issuer);
        }
        [$signed, $refusal] = $this->signatureChecks[$pair];
        if ($refusal !== null) {
            self::record($failure, $refusal);
        }

        return $signed;
    }

    /**
     * @return array{bool, ?ChainBuildingException}
     */
    private function checkSignature(Certificate $subject, Certificate $issuer): array
    {
        try {
            if (!$subject->isSignedBy($issuer)) {
                return [false, new ChainBuildingException(ChainBuildingException::REASON_SIGNATURE, \sprintf('%s is not signed by %s', $subject->subjectDn(), $issuer->subjectDn()))];
            }
            $violation = $this->constraints->violation($subject->signatureAlgorithm(), $issuer->publicKey());
        } catch (CryptoException $e) {
            // An algorithm allkiri does not verify, or an issuer key it cannot read.
            return [false, new ChainBuildingException(ChainBuildingException::REASON_UNSUPPORTED_ALGORITHM, $e->getMessage())];
        }
        if ($violation !== null) {
            return [false, new ChainBuildingException(ChainBuildingException::REASON_ALGORITHM_NOT_ACCEPTED, \sprintf('%s is %s', $subject->subjectDn(), $violation))];
        }

        return [true, null];
    }

    /**
     * Whether a CA's own constraints let it issue the certificate above
     * everything already in the path.
     *
     * The path length counts the CA certificates between this issuer and the
     * leaf, leaving out self-issued ones, as RFC 5280 §6.1.4 does; a trust
     * anchor's limit is held to as well. An intermediate that restricts its key
     * usage must allow keyCertSign.
     *
     * @param non-empty-list<Certificate> $below the path so far, leaf first, ending with the certificate this one would issue
     */
    private function mayIssue(Certificate $issuer, array $below, bool $intermediate, ?ChainBuildingException &$failure): bool
    {
        $limit = $issuer->pathLenConstraint();
        if ($limit !== null) {
            $following = 0;
            foreach (\array_slice($below, 1) as $certificate) {
                if (!$certificate->isSelfIssued()) {
                    ++$following;
                }
            }
            if ($following > $limit) {
                self::record($failure, new ChainBuildingException(ChainBuildingException::REASON_PATH_LENGTH, \sprintf('%s allows %d CA certificates below it, and the path has %d', $issuer->subjectDn(), $limit, $following)));

                return false;
            }
        }
        if ($intermediate && $issuer->hasExtension('id-ce-keyUsage') && !\in_array('keyCertSign', $issuer->keyUsage(), true)) {
            self::record($failure, new ChainBuildingException(ChainBuildingException::REASON_CA_KEY_USAGE, \sprintf('%s is not allowed to sign certificates: its key usage lacks keyCertSign', $issuer->subjectDn())));

            return false;
        }

        return true;
    }

    /**
     * Keep the failure that got furthest. Among equals, a missing issuer or an
     * overlong chain keeps the first one found, and anything else the latest.
     *
     * @param-out ChainBuildingException $failure
     */
    private static function record(?ChainBuildingException &$failure, ChainBuildingException $new): void
    {
        if ($failure === null) {
            $failure = $new;

            return;
        }
        $current = self::FAILURE_RANKS[$failure->reason] ?? self::RANK_PAST_A_SIGNATURE;
        $rank = self::FAILURE_RANKS[$new->reason] ?? self::RANK_PAST_A_SIGNATURE;
        if ($rank > $current || ($rank === $current && $rank >= self::FAILURE_RANKS[ChainBuildingException::REASON_SIGNATURE])) {
            $failure = $new;
        }
    }
}
