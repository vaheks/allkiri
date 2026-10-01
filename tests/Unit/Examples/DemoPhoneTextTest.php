<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Examples;

use Allkiri\Demo\PhoneText;
use Allkiri\MobileId\DisplayTextFormat;
use Allkiri\MobileId\MobileIdConfiguration;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../../examples/demo-app/config.php';

/**
 * The sentences the demo puts on a phone, from ALLKIRI_AUTH_TEXT and
 * ALLKIRI_SIGN_TEXT. A text that does not fit stops the demo at start-up,
 * naming the setting, rather than halfway through someone's sign-in.
 */
#[CoversNothing]
final class DemoPhoneTextTest extends TestCase
{
    public function testAnEstonianTextReachesBothServices(): void
    {
        $text = PhoneText::fromSetting('ALLKIRI_AUTH_TEXT', 'Logi sisse ERISesse', 'Log in to the allkiri demo', 'Log in');

        self::assertSame('Logi sisse ERISesse', $text->interactions()->interactions[0]->text);
        $mobileId = $text->forMobileId(MobileIdConfiguration::demo());
        self::assertSame('Logi sisse ERISesse', $mobileId->displayText);
        self::assertSame(DisplayTextFormat::Gsm7, $mobileId->displayTextFormat);

        // "õ" is not in GSM-7, so Mobile-ID gets the text in UCS-2 instead.
        $signing = PhoneText::fromSetting('ALLKIRI_SIGN_TEXT', 'Allkirjasta mängijalitsents nõusolekuga', 'Sign the uploaded file', 'Sign the uploaded file');
        self::assertSame(DisplayTextFormat::Ucs2, $signing->forMobileId(MobileIdConfiguration::demo())->displayTextFormat);
    }

    public function testTheDefaultsAreUsedWhenNothingIsSet(): void
    {
        $text = PhoneText::fromSetting('ALLKIRI_AUTH_TEXT', '', 'Log in to the allkiri demo', 'Log in');

        self::assertSame('Log in to the allkiri demo', $text->text);
        self::assertSame('Log in', $text->pinText);
    }

    public function testATextTooLongForThePinDialogueNamesItsSetting(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('ALLKIRI_SIGN_TEXT cannot be shown on a phone');

        PhoneText::fromSetting('ALLKIRI_SIGN_TEXT', str_repeat('Allkirjasta ', 6), 'Sign the uploaded file', 'Sign the uploaded file');
    }
}
