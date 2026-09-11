<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\MobileId;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\MobileId\DisplayTextFormat;
use Allkiri\MobileId\MobileIdConfiguration;
use Allkiri\MobileId\MobileIdIdentity;
use Allkiri\MobileId\MobileIdLanguage;
use Allkiri\MobileId\MobileIdResult;
use Allkiri\MobileId\MobileIdSession;
use Allkiri\MobileId\VerificationCode;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class MobileIdValueObjectsTest extends TestCase
{
    // --- identity -----------------------------------------------------------

    public function testIdentityKeepsBothPartsAndNamesTheCountry(): void
    {
        $identity = new MobileIdIdentity('+37200000766', '60001019906');

        self::assertSame('+37200000766', $identity->phoneNumber);
        self::assertSame('60001019906', $identity->nationalIdentityNumber);
        self::assertSame('EE', $identity->country());
        self::assertSame('LT', (new MobileIdIdentity('+37060000666', '51001091072'))->country());
        self::assertNull((new MobileIdIdentity('+4915112345678', '60001019906'))->country());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function badIdentities(): iterable
    {
        yield 'no plus' => ['37200000766', '60001019906'];
        yield 'spaces' => ['+372 5555 5555', '60001019906'];
        yield 'letters' => ['+3720000076a', '60001019906'];
        yield 'empty phone' => ['', '60001019906'];
        yield 'short code' => ['+37200000766', '6000101990'];
        yield 'long code' => ['+37200000766', '600010199060'];
        yield 'code with letters' => ['+37200000766', '6000101990X'];
    }

    #[DataProvider('badIdentities')]
    public function testIdentityRefusesMalformedInput(string $phone, string $code): void
    {
        $this->expectException(InvalidArgumentException::class);

        new MobileIdIdentity($phone, $code);
    }

    // --- verification code --------------------------------------------------

    /**
     * SK's own worked example: the first six bits of the hash and its last
     * seven, concatenated, read as a decimal number.
     */
    public function testVerificationCodeMatchesTheDocumentedExample(): void
    {
        $hash = hex2bin('2f665f6a6999e0ef0752e00ec9f453adf59d8cb6');
        self::assertIsString($hash);

        self::assertSame('1462', VerificationCode::forHash($hash));
    }

    public function testVerificationCodeIsAlwaysFourDigits(): void
    {
        self::assertSame('0000', VerificationCode::forHash("\x00\x00"));
        self::assertSame('8191', VerificationCode::forHash("\xFC\xFF"));
        self::assertMatchesRegularExpression('/^\d{4}$/', VerificationCode::forHash(random_bytes(32)));
    }

    public function testVerificationCodeNeedsTwoBytes(): void
    {
        $this->expectException(InvalidArgumentException::class);

        VerificationCode::forHash("\x01");
    }

    // --- results ------------------------------------------------------------

    public function testEveryPublishedResultHasAMessage(): void
    {
        foreach (MobileIdResult::cases() as $result) {
            self::assertNotSame('', $result->message(), $result->value . ' has no message');
        }
    }

    public function testOnlyTransientResultsAreWorthRetrying(): void
    {
        self::assertTrue(MobileIdResult::Timeout->isWorthRetrying());
        self::assertTrue(MobileIdResult::UserCancelled->isWorthRetrying());
        self::assertTrue(MobileIdResult::PhoneAbsent->isWorthRetrying());
        self::assertTrue(MobileIdResult::DeliveryError->isWorthRetrying());

        self::assertFalse(MobileIdResult::NotMidClient->isWorthRetrying());
        self::assertFalse(MobileIdResult::SignatureHashMismatch->isWorthRetrying());
        self::assertFalse(MobileIdResult::SimError->isWorthRetrying());
    }

    // --- language and display text -----------------------------------------

    public function testLanguageFollowsTheLocale(): void
    {
        self::assertSame(MobileIdLanguage::Estonian, MobileIdLanguage::forLocale('et_EE'));
        self::assertSame(MobileIdLanguage::Russian, MobileIdLanguage::forLocale('ru'));
        self::assertSame(MobileIdLanguage::Lithuanian, MobileIdLanguage::forLocale('lt-LT'));
        self::assertSame(MobileIdLanguage::English, MobileIdLanguage::forLocale('de'));
    }

    public function testDisplayTextLengthIsCountedInCharactersNotBytes(): void
    {
        self::assertSame(100, DisplayTextFormat::Gsm7->maximumLength());
        self::assertSame(50, DisplayTextFormat::Ucs2->maximumLength());

        // "ä" is two bytes of UTF-8 but one character in both formats.
        self::assertSame(6, DisplayTextFormat::Gsm7->lengthOf('Männik'));
        self::assertSame(6, DisplayTextFormat::Ucs2->lengthOf('Männik'));

        // Extension-table characters cost two.
        self::assertSame(2, DisplayTextFormat::Gsm7->lengthOf('€'));
        self::assertSame(1, DisplayTextFormat::Ucs2->lengthOf('€'));
    }

    /**
     * The service does not refuse characters outside GSM-7, it replaces them
     * with spaces, so "Nõustun" would reach the phone as "N ustun".
     */
    public function testGsm7NamesTheCharactersItWouldTurnIntoSpaces(): void
    {
        self::assertSame(['õ'], DisplayTextFormat::Gsm7->unsupportedCharacters('Nõustun'));
        self::assertSame(['š', 'ž'], DisplayTextFormat::Gsm7->unsupportedCharacters('šž šž'));
        self::assertSame([], DisplayTextFormat::Gsm7->unsupportedCharacters('Männik & Pöör, 10 EUR?'));
        self::assertSame([], DisplayTextFormat::Ucs2->unsupportedCharacters('Нõustun ž'));
    }

    public function testGsm7AllowsAtMostFiveExtensionCharacters(): void
    {
        self::assertFalse(DisplayTextFormat::Gsm7->exceedsExtensionLimit('[]{}|'));
        self::assertTrue(DisplayTextFormat::Gsm7->exceedsExtensionLimit('[]{}|~'));
        self::assertFalse(DisplayTextFormat::Ucs2->exceedsExtensionLimit('[]{}|~'));
    }

    public function testTheFormatCanBeChosenForTheText(): void
    {
        self::assertSame(DisplayTextFormat::Gsm7, DisplayTextFormat::forText('Allkirjasta leping'));
        self::assertSame(DisplayTextFormat::Ucs2, DisplayTextFormat::forText('Nõustun tingimustega'));
        self::assertSame(DisplayTextFormat::Ucs2, DisplayTextFormat::forText(str_repeat('a', 101)));
    }

    // --- configuration ------------------------------------------------------

    public function testDemoConfigurationIsRecognisable(): void
    {
        $configuration = MobileIdConfiguration::demo('Allkirjasta leping');

        self::assertTrue($configuration->isDemo());
        self::assertSame(MobileIdConfiguration::DEMO_URL, $configuration->url);
        self::assertSame('Allkirjasta leping', $configuration->displayText);
        self::assertFalse(MobileIdConfiguration::production('11111111-2222-3333-4444-555555555555', 'Allkiri OÜ')->isDemo());
    }

    public function testConfigurationRefusesAnIdentifierThatIsNotAUuid(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new MobileIdConfiguration(MobileIdConfiguration::DEMO_URL, 'not-a-uuid', 'DEMO');
    }

    public function testConfigurationRefusesADisplayTextThatWouldBeTruncated(): void
    {
        $this->expectException(InvalidArgumentException::class);

        MobileIdConfiguration::demo()->withDisplayText(str_repeat('a', 51), DisplayTextFormat::Ucs2);
    }

    public function testConfigurationRefusesADisplayTextThatWouldReachThePhoneMangled(): void
    {
        $this->expectExceptionMessageMatches('/replace them with spaces/');

        MobileIdConfiguration::demo()->withDisplayText('Nõustun', DisplayTextFormat::Gsm7);
    }

    public function testConfigurationAcceptsTheSameTextInUcs2(): void
    {
        $configuration = MobileIdConfiguration::demo()->withDisplayText('Nõustun', DisplayTextFormat::Ucs2);

        self::assertSame('Nõustun', $configuration->displayText);
        self::assertSame(DisplayTextFormat::Ucs2, $configuration->displayTextFormat);
    }

    public function testConfigurationRefusesATimeoutTheServiceWouldClamp(): void
    {
        $this->expectException(InvalidArgumentException::class);

        MobileIdConfiguration::demo()->withTimeouts(500, 120);
    }

    public function testConfigurationRefusesAPollTimeoutTheServiceWouldIgnore(): void
    {
        $this->expectException(InvalidArgumentException::class);

        MobileIdConfiguration::demo()->withTimeouts(120_000, 300);
    }

    /**
     * A long poll must not be cut short by the HTTP client's own timeout.
     */
    public function testHttpTimeoutLeavesRoomForTheLongPoll(): void
    {
        self::assertSame(15, MobileIdConfiguration::demo()->httpTimeoutSeconds());
        self::assertSame(65, MobileIdConfiguration::demo()->withTimeouts(60_000, 300)->httpTimeoutSeconds());
    }

    public function testWithersKeepEverythingElse(): void
    {
        $configuration = MobileIdConfiguration::demo('Tere')->withLanguage(MobileIdLanguage::Russian)->withTimeouts(5_000, 60);

        self::assertSame('Tere', $configuration->displayText);
        self::assertSame(MobileIdLanguage::Russian, $configuration->language);
        self::assertSame(5_000, $configuration->pollTimeoutMs);
        self::assertSame(60, $configuration->sessionTimeoutSeconds);
    }

    // --- session ------------------------------------------------------------

    public function testSessionSurvivesJsonRoundTrip(): void
    {
        $session = new MobileIdSession(
            'b1e1f0dd-0000-4000-8000-000000000001',
            MobileIdSession::TYPE_AUTHENTICATION,
            '1462',
            new MobileIdIdentity('+37200000766', '60001019906'),
            random_bytes(64),
        );

        $restored = MobileIdSession::fromJson(json_encode($session, JSON_THROW_ON_ERROR));

        self::assertSame($session->sessionId, $restored->sessionId);
        self::assertSame($session->type, $restored->type);
        self::assertSame($session->verificationCode, $restored->verificationCode);
        self::assertSame($session->challenge, $restored->challenge);
        self::assertSame($session->identity->phoneNumber, $restored->identity->phoneNumber);
    }

    public function testSessionRefusesAnUnknownType(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new MobileIdSession('x', 'certificate', '1462', new MobileIdIdentity('+37200000766', '60001019906'));
    }
}
