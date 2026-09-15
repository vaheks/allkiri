<?php

declare(strict_types=1);

namespace Allkiri\Validation;

use Allkiri\Trust\TrustAnchor;
use Allkiri\Trust\TrustedList\TrustedListStatus;
use Allkiri\Trust\TrustStore;
use Allkiri\Trust\WithoutExpiredListsTrustStore;
use Allkiri\Validation\Report\Finding;
use Allkiri\Validation\Report\Indication;
use Allkiri\Validation\Report\SubIndication;

/**
 * What one signature's validation learns about the trusted lists it rests on.
 *
 * By default an overdue list is still used, and each one that the signer's
 * CA, a timestamp authority or a listed responder actually rested on becomes a
 * warning. With a grace period, anchors from a list overdue by longer are left
 * out of the store the checks use; when a check then comes up empty, it is run
 * once more against every anchor so the report can name the list.
 *
 * @internal
 */
final class TrustedListExpiry
{
    /** The store the checks decide trust with: without refused lists when the policy has a grace period. */
    public readonly TrustStore $store;

    /** @var array<string, array{list: TrustedListStatus, roles: list<string>}> expired list label => what rests on it */
    private array $reliedOn = [];

    /**
     * @param TrustStore $unfiltered every anchor, for finding a certificate rather than trusting it
     */
    public function __construct(
        public readonly TrustStore $unfiltered,
        private readonly \DateTimeImmutable $at,
        private readonly ?int $graceSeconds,
    ) {
        $this->store = $graceSeconds === null ? $unfiltered : new WithoutExpiredListsTrustStore($unfiltered, $at, $graceSeconds);
    }

    /**
     * Note that part of the signature rests on this anchor.
     */
    public function relyOn(TrustAnchor $anchor, string $role): void
    {
        $expired = $anchor->trustedList?->expiredAt($this->at);
        if ($expired === null) {
            return;
        }
        $entry = $this->reliedOn[$expired->label] ?? ['list' => $expired, 'roles' => []];
        if (!\in_array($role, $entry['roles'], true)) {
            $entry['roles'][] = $role;
        }
        $this->reliedOn[$expired->label] = $entry;
    }

    /**
     * The anchor a check came up without because its list was refused: the one
     * the check finds when run again against every anchor. Null when refusal is
     * off, or when the check fails for some other reason.
     *
     * @param \Closure(TrustStore): ?TrustAnchor $check
     */
    public function refusedAnchor(\Closure $check): ?TrustAnchor
    {
        if ($this->graceSeconds === null) {
            return null;
        }
        $anchor = $check($this->unfiltered);

        return $anchor?->trustedList?->expiredAt($this->at, $this->graceSeconds) !== null ? $anchor : null;
    }

    /**
     * The error for a part of the signature left without its anchor.
     *
     * The sub-indication is the one the anchor's absence would give, so a
     * caller branching on it sees the same thing whether the anchor was never
     * configured or came from a list overdue for too long.
     */
    public function refusal(TrustAnchor $anchor, string $role, SubIndication $subIndication): Finding
    {
        $grace = $this->graceSeconds ?? 0;
        $expired = $anchor->trustedList?->expiredAt($this->at, $grace) ?? throw new \LogicException('The anchor is not from a refused list');

        return Finding::error(
            FindingCodes::TRUSTED_LIST_EXPIRED,
            $expired->nextUpdate === null
                ? \sprintf('Trusted list "%s" names no next update, so under this policy %s is not trusted', $expired->label, $role)
                : \sprintf('Trusted list "%s" was due for its next update on %s and has not had one within the %d seconds the policy allows, so %s is not trusted', $expired->label, $expired->nextUpdate->format(DATE_ATOM), $grace, $role),
            Indication::Indeterminate,
            $subIndication,
        );
    }

    /**
     * One warning for each overdue list something rested on.
     *
     * @return list<Finding>
     */
    public function warnings(): array
    {
        $warnings = [];
        foreach ($this->reliedOn as $entry) {
            $list = $entry['list'];
            $warnings[] = Finding::warning(
                FindingCodes::TRUSTED_LIST_EXPIRED,
                \sprintf(
                    '%s; %s %s on it',
                    $list->nextUpdate === null
                        ? \sprintf('Trusted list "%s" names no next update', $list->label)
                        : \sprintf('Trusted list "%s" was due for its next update on %s and has not had one', $list->label, $list->nextUpdate->format(DATE_ATOM)),
                    implode(' and ', $entry['roles']),
                    \count($entry['roles']) === 1 ? 'rests' : 'rest',
                ),
            );
        }

        return $warnings;
    }
}
