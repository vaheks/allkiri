<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

/**
 * How the text on the phone is encoded, which decides both how much of it fits
 * and which characters survive the trip.
 *
 * GSM-7 takes 100 characters of the GSM 03.38 default alphabet, of which at
 * most five may come from its extension table. Anything else the service
 * silently replaces with a space, so "Nõustun" arrives as "N ustun". Estonian
 * õ, š and ž and every Cyrillic letter need UCS-2, which takes 50 characters
 * of anything.
 */
enum DisplayTextFormat: string
{
    case Gsm7 = 'GSM-7';
    case Ucs2 = 'UCS-2';

    // Single-quoted on purpose: PHP allows high-byte characters in identifiers,
    // so "$¥" inside a double-quoted string is read as a variable.

    /** The GSM 03.38 default alphabet. Each of these counts as one character. */
    private const GSM7_BASIC = '@£$¥èéùìòÇ' . "\n" . 'Øø' . "\r"
        . 'ÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !"#¤%&\'()*+,-./0123456789:;<=>?'
        . '¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà';

    /** The extension table. Each counts as two characters, and at most five may appear. */
    private const GSM7_EXTENDED = '^{}\\[~]|€';

    private const GSM7_MAX_EXTENDED = 5;

    public function maximumLength(): int
    {
        return match ($this) {
            self::Gsm7 => 100,
            self::Ucs2 => 50,
        };
    }

    /**
     * How long the text is in the units this format counts: characters, with
     * GSM-7 extension characters counting double because that is what they
     * cost on the wire.
     */
    public function lengthOf(string $text): int
    {
        if ($this === self::Ucs2) {
            return mb_strlen($text, 'UTF-8');
        }

        $length = 0;
        foreach (self::characters($text) as $character) {
            $length += mb_strpos(self::GSM7_EXTENDED, $character, 0, 'UTF-8') !== false ? 2 : 1;
        }

        return $length;
    }

    /**
     * The characters this format cannot carry, which the service would replace
     * with spaces before the person ever sees them.
     *
     * @return list<string> in the order they appear, without repeats
     */
    public function unsupportedCharacters(string $text): array
    {
        if ($this === self::Ucs2) {
            return [];
        }

        $unsupported = [];
        foreach (self::characters($text) as $character) {
            if (mb_strpos(self::GSM7_BASIC, $character, 0, 'UTF-8') === false
                && mb_strpos(self::GSM7_EXTENDED, $character, 0, 'UTF-8') === false
                && !\in_array($character, $unsupported, true)
            ) {
                $unsupported[] = $character;
            }
        }

        return $unsupported;
    }

    /**
     * Whether the text uses more than the five extension characters allowed.
     */
    public function exceedsExtensionLimit(string $text): bool
    {
        if ($this === self::Ucs2) {
            return false;
        }

        $extended = 0;
        foreach (self::characters($text) as $character) {
            if (mb_strpos(self::GSM7_EXTENDED, $character, 0, 'UTF-8') !== false) {
                ++$extended;
            }
        }

        return $extended > self::GSM7_MAX_EXTENDED;
    }

    /**
     * The format that carries this text unharmed, preferring the one that
     * leaves the most room.
     */
    public static function forText(string $text): self
    {
        $gsm7 = self::Gsm7;
        if ($gsm7->unsupportedCharacters($text) === []
            && !$gsm7->exceedsExtensionLimit($text)
            && $gsm7->lengthOf($text) <= $gsm7->maximumLength()
        ) {
            return $gsm7;
        }

        return self::Ucs2;
    }

    /**
     * @return list<string>
     */
    private static function characters(string $text): array
    {
        $characters = preg_split('//u', $text, -1, PREG_SPLIT_NO_EMPTY);

        return $characters === false ? [] : $characters;
    }
}
