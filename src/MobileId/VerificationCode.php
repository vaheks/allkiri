<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

use Allkiri\Exception\InvalidArgumentException;

/**
 * The four digits shown on screen next to the four digits on the phone.
 *
 * They are derived from the hash being signed, so a person comparing them is
 * checking that the phone is about to sign what the website asked for. Always
 * show it; without it Mobile-ID gives no protection against a request the user
 * did not start.
 *
 * The rule (SK's MID specification): six bits from the start of the hash and
 * seven bits from its end, read as one 13-bit number.
 */
final class VerificationCode
{
    private function __construct() {}

    /**
     * @param string $hash the raw bytes being signed, not hex or base64
     *
     * @return string four digits, zero-padded
     */
    public static function forHash(string $hash): string
    {
        if (\strlen($hash) < 2) {
            throw new InvalidArgumentException('A verification code needs at least two bytes of hash');
        }
        $first = \ord($hash[0]) >> 2;
        $last = \ord($hash[\strlen($hash) - 1]) & 0x7F;

        return \sprintf('%04d', ($first << 7) | $last);
    }
}
