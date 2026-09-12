<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\SmartId;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\SmartId\DeviceLink;
use Allkiri\SmartId\SmartIdClient;
use Allkiri\SmartId\SmartIdConfiguration;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The device link is the one place where this library has to reproduce a string
 * byte for byte or the Smart-ID app will refuse it, so these tests pin the
 * order of the query parameters and the shape of the signed payload rather than
 * merely checking that something comes out.
 */
#[CoversNothing]
final class DeviceLinkTest extends TestCase
{
    private const SECRET = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=';

    private static function link(
        string $linkType = DeviceLink::TYPE_QR,
        string $sessionType = DeviceLink::SESSION_AUTHENTICATION,
        string $payload = 'Y2hhbGxlbmdl',
        ?string $initialCallbackUrl = null,
    ): DeviceLink {
        return new DeviceLink(
            SmartIdConfiguration::SCHEME_DEMO,
            'https://smart-id.test/dl',
            $linkType,
            $sessionType,
            'the-session-token',
            base64_encode('DEMO'),
            base64_encode('[{"type":"displayTextAndPIN","displayText60":"Log in"}]'),
            $payload,
            'est',
            $initialCallbackUrl,
        );
    }

    public function testTheQueryParametersComeInTheOrderTheAppExpects(): void
    {
        $url = self::link()->unprotectedUrl(7);

        self::assertSame(
            'https://smart-id.test/dl?deviceLinkType=QR&elapsedSeconds=7&sessionToken=the-session-token&sessionType=auth&version=1.0&lang=est',
            $url,
        );
    }

    public function testANonQrLinkCarriesNoElapsedSeconds(): void
    {
        $url = self::link(DeviceLink::TYPE_WEB2APP)->unprotectedUrl();

        self::assertSame(
            'https://smart-id.test/dl?deviceLinkType=Web2App&sessionToken=the-session-token&sessionType=auth&version=1.0&lang=est',
            $url,
        );
    }

    public function testElapsedSecondsAreRefusedOnANonQrLink(): void
    {
        $this->expectExceptionMessageMatches('/Only a QR link/');

        self::link(DeviceLink::TYPE_APP2APP)->unprotectedUrl(3);
    }

    /**
     * The eight parts, in order, joined by pipes. The signature protocol is
     * decided by the session type, and the two optional parts are empty rather
     * than absent.
     */
    public function testTheSignedPayloadHasAllEightPartsInOrder(): void
    {
        $link = self::link();
        $unprotected = $link->unprotectedUrl(0);

        $parts = explode('|', $link->payload($unprotected));

        self::assertCount(8, $parts);
        self::assertSame(SmartIdConfiguration::SCHEME_DEMO, $parts[0]);
        self::assertSame(SmartIdClient::PROTOCOL_ACSP_V2, $parts[1]);
        self::assertSame('Y2hhbGxlbmdl', $parts[2]);
        self::assertSame(base64_encode('DEMO'), $parts[3]);
        self::assertSame('', $parts[4], 'no brokered relying party');
        self::assertSame(base64_encode('[{"type":"displayTextAndPIN","displayText60":"Log in"}]'), $parts[5]);
        self::assertSame('', $parts[6], 'no callback URL');
        self::assertSame($unprotected, $parts[7]);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function sessionProtocols(): iterable
    {
        yield 'authentication' => [DeviceLink::SESSION_AUTHENTICATION, SmartIdClient::PROTOCOL_ACSP_V2];
        yield 'signature' => [DeviceLink::SESSION_SIGNATURE, SmartIdClient::PROTOCOL_RAW_DIGEST];
        yield 'certificate choice' => [DeviceLink::SESSION_CERTIFICATE_CHOICE, ''];
    }

    #[DataProvider('sessionProtocols')]
    public function testTheSessionTypeDecidesTheProtocolInThePayload(string $sessionType, string $expected): void
    {
        $link = self::link(sessionType: $sessionType);

        self::assertSame($expected, explode('|', $link->payload($link->unprotectedUrl(0)))[1]);
    }

    public function testTheCallbackUrlIsPartOfWhatIsSigned(): void
    {
        $link = self::link(DeviceLink::TYPE_WEB2APP, initialCallbackUrl: 'https://example.test/back');

        self::assertSame('https://example.test/back', explode('|', $link->payload($link->unprotectedUrl()))[6]);
    }

    /**
     * The authentication code is an HMAC keyed with the decoded session secret,
     * rendered as base64url without padding.
     */
    public function testTheAuthenticationCodeIsAUrlSafeHmac(): void
    {
        $link = self::link();
        $unprotected = $link->unprotectedUrl(0);

        $code = $link->authenticationCode(self::SECRET, $unprotected);

        $key = base64_decode(self::SECRET, true);
        self::assertIsString($key);
        $expected = rtrim(strtr(base64_encode(hash_hmac('sha256', $link->payload($unprotected), $key, true)), '+/', '-_'), '=');

        self::assertSame($expected, $code);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $code);
        self::assertStringNotContainsString('=', $code);
    }

    public function testTheFinishedLinkEndsWithItsAuthenticationCode(): void
    {
        $link = self::link();

        $url = $link->url(self::SECRET, 12);

        $unprotected = $link->unprotectedUrl(12);
        self::assertSame($unprotected . '&authCode=' . $link->authenticationCode(self::SECRET, $unprotected), $url);
    }

    /**
     * A QR code is rebuilt about once a second, and the elapsed seconds are
     * inside what the code covers, so each second's link has its own code.
     */
    public function testEverySecondProducesADifferentCode(): void
    {
        $link = self::link();

        $codes = [];
        for ($second = 0; $second < 5; ++$second) {
            $codes[] = $link->url(self::SECRET, $second);
        }

        self::assertCount(5, array_unique($codes));
    }

    public function testASecretThatIsNotBase64IsRefused(): void
    {
        $this->expectExceptionMessageMatches('/not base64/');

        self::link()->url('not base64 at all!!');
    }

    /**
     * @return iterable<string, array{string, string, string, string, string}>
     */
    public static function badParameters(): iterable
    {
        $base = 'https://smart-id.test/dl';
        yield 'unknown link type' => [$base, 'Bluetooth', DeviceLink::SESSION_AUTHENTICATION, 'token', 'est'];
        yield 'unknown session type' => [$base, DeviceLink::TYPE_QR, 'login', 'token', 'est'];
        yield 'two-letter language' => [$base, DeviceLink::TYPE_QR, DeviceLink::SESSION_AUTHENTICATION, 'token', 'et'];
        yield 'empty base' => ['', DeviceLink::TYPE_QR, DeviceLink::SESSION_AUTHENTICATION, 'token', 'est'];
        yield 'empty token' => [$base, DeviceLink::TYPE_QR, DeviceLink::SESSION_AUTHENTICATION, '', 'est'];
    }

    #[DataProvider('badParameters')]
    public function testMalformedParametersAreRefused(string $base, string $linkType, string $sessionType, string $sessionToken, string $language): void
    {
        $this->expectException(InvalidArgumentException::class);

        new DeviceLink(
            SmartIdConfiguration::SCHEME_DEMO,
            $base,
            $linkType,
            $sessionType,
            $sessionToken,
            base64_encode('DEMO'),
            'e30=',
            'Y2hhbGxlbmdl',
            $language,
        );
    }

    public function testABaseUrlThatAlreadyHasAQueryIsExtended(): void
    {
        $link = new DeviceLink(
            SmartIdConfiguration::SCHEME_DEMO,
            'https://smart-id.test/dl?rp=1',
            DeviceLink::TYPE_QR,
            DeviceLink::SESSION_AUTHENTICATION,
            'token',
            base64_encode('DEMO'),
            'e30=',
            'Y2hhbGxlbmdl',
        );

        self::assertStringStartsWith('https://smart-id.test/dl?rp=1&deviceLinkType=QR', $link->unprotectedUrl(0));
    }
}
