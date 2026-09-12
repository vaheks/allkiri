<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

/**
 * What the Smart-ID app shows the person before asking for their PIN.
 *
 * `DisplayTextAndPin` is the plain dialogue. `ConfirmationMessage` gives room
 * for a longer sentence on a screen of its own. The verification-code choice
 * makes the app offer three codes of which only one matches the website, which
 * is the strongest protection against someone else starting the session, and
 * the one SK recommends for anything that matters.
 */
enum InteractionType: string
{
    case DisplayTextAndPin = 'displayTextAndPIN';
    case ConfirmationMessage = 'confirmationMessage';
    case ConfirmationMessageAndVerificationCodeChoice = 'confirmationMessageAndVerificationCodeChoice';

    /**
     * The JSON field the text belongs in, which also names its limit.
     */
    public function textField(): string
    {
        return $this === self::DisplayTextAndPin ? 'displayText60' : 'displayText200';
    }

    public function maximumLength(): int
    {
        return $this === self::DisplayTextAndPin ? 60 : 200;
    }

    /**
     * Device-link flows cannot offer the verification-code choice: there is no
     * code to compare, because the person came from the link itself.
     */
    public function isSupportedInDeviceLink(): bool
    {
        return $this !== self::ConfirmationMessageAndVerificationCodeChoice;
    }
}
