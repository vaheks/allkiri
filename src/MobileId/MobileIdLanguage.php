<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

/**
 * The language of the text the phone shows. Mobile-ID supports these four.
 */
enum MobileIdLanguage: string
{
    case Estonian = 'EST';
    case English = 'ENG';
    case Russian = 'RUS';
    case Lithuanian = 'LIT';

    /**
     * The closest match for a two-letter locale, English when there is none.
     */
    public static function forLocale(string $locale): self
    {
        return match (strtolower(substr($locale, 0, 2))) {
            'et' => self::Estonian,
            'ru' => self::Russian,
            'lt' => self::Lithuanian,
            default => self::English,
        };
    }
}
