<?php

declare(strict_types=1);

namespace Allkiri\Xml;

/**
 * Reads the one date format XML documents state times in.
 *
 * `new DateTimeImmutable($text)` takes far more than a date. It also takes
 * "now", "tomorrow", "+1 year" and the rest of PHP's relative formats, so a
 * document that says `<SigningTime>now</SigningTime>` would parse, and the time
 * it produced would be the moment of reading rather than anything the document
 * says. A signature claiming to have been made at the instant it is validated
 * is not a value to carry into a report.
 *
 * So the shape is checked first, and only then handed to the constructor, which
 * by then has nothing left to interpret. The reader of the JSON an application
 * stores between requests refuses a loose date for the same reason.
 *
 * @internal
 */
final class XsdDateTime
{
    /**
     * xsd:dateTime — YYYY-MM-DDThh:mm:ss, with optional fractional seconds and
     * an optional zone offset. Anchored with \z: a trailing newline is not part
     * of a date.
     */
    private const PATTERN = '/^(?<date>-?\d{4,}-\d{2}-\d{2})T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?\z/';

    private function __construct() {}

    /**
     * The time this text states, in UTC, or null when it does not state one.
     */
    public static function tryParse(?string $text): ?\DateTimeImmutable
    {
        if ($text === null) {
            return null;
        }
        $text = trim($text);
        if (preg_match(self::PATTERN, $text, $stated) !== 1) {
            return null;
        }

        try {
            // The shape is settled, so nothing here is a relative format.
            $parsed = new \DateTimeImmutable($text);
        } catch (\Exception) {
            return null;
        }

        // A date that does not exist is carried forward rather than refused:
        // the 31st of February parses, as the 3rd of March. A document stating a
        // day that is not a day has not stated one, so the day that comes back
        // has to be the day that was written. Compared before the zone is
        // changed, because that is what moves the date.
        if ($parsed->format('Y-m-d') !== $stated['date']) {
            return null;
        }

        return $parsed->setTimezone(new \DateTimeZone('UTC'));
    }
}
