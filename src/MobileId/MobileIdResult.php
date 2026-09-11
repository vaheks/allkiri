<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

/**
 * How a Mobile-ID session ended.
 *
 * Only `Ok` means a signature was produced. Everything else is a fact about
 * the person or their phone, not a fault in the request, and deserves a
 * message the user can act on.
 */
enum MobileIdResult: string
{
    case Ok = 'OK';

    /** The person did not answer in time (about two minutes). */
    case Timeout = 'TIMEOUT';

    /** No active Mobile-ID certificates for this person and phone. */
    case NotMidClient = 'NOT_MID_CLIENT';

    /** The person declined. */
    case UserCancelled = 'USER_CANCELLED';

    /** The SIM produced a signature over something else; the phone is misconfigured. */
    case SignatureHashMismatch = 'SIGNATURE_HASH_MISMATCH';

    /** The phone was unreachable: switched off, out of coverage. */
    case PhoneAbsent = 'PHONE_ABSENT';

    /** The message could not be delivered to the phone. */
    case DeliveryError = 'DELIVERY_ERROR';

    /** The SIM answered, but not with anything usable. */
    case SimError = 'SIM_ERROR';

    /**
     * Something a person can be told, in English. Translate as needed; the
     * enum case is the stable thing to branch on.
     */
    public function message(): string
    {
        return match ($this) {
            self::Ok => 'The operation completed.',
            self::Timeout => 'There was no answer on the phone in time.',
            self::NotMidClient => 'This person has no active Mobile-ID.',
            self::UserCancelled => 'The operation was cancelled on the phone.',
            self::SignatureHashMismatch => 'The phone signed something other than what was sent; the SIM needs to be reissued.',
            self::PhoneAbsent => 'The phone could not be reached.',
            self::DeliveryError => 'The request could not be delivered to the phone.',
            self::SimError => 'The SIM card did not answer correctly.',
        };
    }

    /**
     * Whether trying again might help. A cancelled or timed-out request might
     * succeed next time; a phone with no Mobile-ID will not.
     */
    public function isWorthRetrying(): bool
    {
        return match ($this) {
            self::Timeout, self::UserCancelled, self::PhoneAbsent, self::DeliveryError => true,
            default => false,
        };
    }
}
