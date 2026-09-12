<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Exception\InvalidArgumentException;

/**
 * The four digits the person compares with their Smart-ID app.
 *
 * Notification flows get the code from the service in the session response.
 * Device-link flows compute it here, from the challenge or digest the session
 * was started with.
 *
 * The rule: SHA-256 the data, read the last two bytes as an unsigned 16-bit
 * big-endian number, and keep its last four decimal digits.
 */
final class VerificationCode
{
    private function __construct() {}

    public static function forData(string $data): string
    {
        if ($data === '') {
            throw new InvalidArgumentException('A verification code needs something to be computed from');
        }
        $digest = hash('sha256', $data, true);
        /** @var array{1: int} $unpacked */
        $unpacked = unpack('n', substr($digest, -2));

        return \sprintf('%04d', $unpacked[1] % 10_000);
    }
}
