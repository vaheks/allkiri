<?php

declare(strict_types=1);

namespace Allkiri\Trust\TrustedList;

/**
 * Which trusted list an anchor was published in, and until when that list
 * was current.
 *
 * A list is due for replacement at its NextUpdate. One that has passed it, or
 * names no next update at all, may be missing withdrawals published since. An
 * anchor reached through the list of lists rests on that list being current as
 * well.
 */
final readonly class TrustedListStatus
{
    public function __construct(
        public string $label,
        public ?\DateTimeImmutable $nextUpdate,
        public ?TrustedListStatus $listOfLists = null,
    ) {}

    public static function of(TrustedList $list, string $label): self
    {
        return new self($label, $list->nextUpdate);
    }

    public function withListOfLists(self $listOfLists): self
    {
        return new self($this->label, $this->nextUpdate, $listOfLists);
    }

    /**
     * The list that is past its next update by more than the grace period at
     * the given time: this one, or else the list of lists it was reached
     * through. Null when both are current.
     */
    public function expiredAt(\DateTimeInterface $time, int $graceSeconds = 0): ?self
    {
        if ($this->nextUpdate === null || $this->nextUpdate->getTimestamp() + $graceSeconds < $time->getTimestamp()) {
            return $this;
        }

        return $this->listOfLists?->expiredAt($time, $graceSeconds);
    }
}
