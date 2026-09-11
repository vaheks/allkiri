<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

use Allkiri\Exception\InvalidArgumentException;

/**
 * Who to reach: a phone number and the national identity number of the person
 * whose SIM it is. Mobile-ID needs both, and checks they belong together.
 */
final readonly class MobileIdIdentity
{
    /**
     * @param string $phoneNumber           in international form, "+37200000766"
     * @param string $nationalIdentityNumber the Estonian isikukood or its Lithuanian equivalent
     */
    public function __construct(
        public string $phoneNumber,
        public string $nationalIdentityNumber,
    ) {
        if (preg_match('/^\+[1-9]\d{6,14}$/', $phoneNumber) !== 1) {
            throw new InvalidArgumentException(\sprintf('"%s" is not a phone number in international form, for example "+37200000766"', $phoneNumber));
        }
        if (preg_match('/^\d{11}$/', $nationalIdentityNumber) !== 1) {
            throw new InvalidArgumentException(\sprintf('"%s" is not an eleven-digit national identity number', $nationalIdentityNumber));
        }
    }

    /**
     * The country the phone number belongs to, as far as the prefix says:
     * "EE" or "LT" for the two Mobile-ID countries, null for anything else.
     */
    public function country(): ?string
    {
        return match (true) {
            str_starts_with($this->phoneNumber, '+372') => 'EE',
            str_starts_with($this->phoneNumber, '+370') => 'LT',
            default => null,
        };
    }

    public function __toString(): string
    {
        return $this->phoneNumber . ' / ' . $this->nationalIdentityNumber;
    }
}
