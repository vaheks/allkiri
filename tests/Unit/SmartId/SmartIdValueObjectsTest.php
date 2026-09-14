<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\SmartId;

use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Exception\InvalidArgumentException;
use Allkiri\SmartId\CertificateLevel;
use Allkiri\SmartId\DocumentNumber;
use Allkiri\SmartId\Interaction;
use Allkiri\SmartId\Interactions;
use Allkiri\SmartId\InteractionType;
use Allkiri\SmartId\RsaPssParameters;
use Allkiri\SmartId\SemanticsIdentifier;
use Allkiri\SmartId\SmartIdConfiguration;
use Allkiri\SmartId\SmartIdEndResult;
use Allkiri\SmartId\VerificationCode;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class SmartIdValueObjectsTest extends TestCase
{
    // --- verification code --------------------------------------------------

    /**
     * SK's own published vectors. All but the first are the code for the
     * SHA-256 of the string, which is how a digest reaches the calculation.
     *
     * @return iterable<string, array{string, string, bool}>
     */
    public static function verificationCodes(): iterable
    {
        yield 'two bytes' => ['4555', "\x1b\xbb", true];
        yield 'hello world' => ['7712', 'Hello World!', false];
        yield 'hedgehogs' => ['4612', "Hedgehogs – why can't they just share the hedge?", false];
        yield 'make my day' => ['7782', 'Go ahead, make my day.', false];
        yield 'bigger boat' => ['1464', "You're gonna need a bigger boat.", false];
        yield 'little friend' => ['4240', "Say 'hello' to my little friend!", false];
    }

    #[DataProvider('verificationCodes')]
    public function testTheVerificationCodeMatchesTheDocumentedVectors(string $expected, string $input, bool $raw): void
    {
        $data = $raw ? $input : hash('sha256', $input, true);

        self::assertSame($expected, VerificationCode::forData($data));
    }

    public function testTheVerificationCodeIsAlwaysFourDigits(): void
    {
        for ($i = 0; $i < 200; ++$i) {
            self::assertMatchesRegularExpression('/^\d{4}$/', VerificationCode::forData(random_bytes(32)));
        }
    }

    public function testTheVerificationCodeNeedsSomethingToComputeFrom(): void
    {
        $this->expectException(InvalidArgumentException::class);

        VerificationCode::forData('');
    }

    // --- semantics identifier -----------------------------------------------

    public function testASemanticsIdentifierRoundTrips(): void
    {
        $identity = SemanticsIdentifier::estonian('40504040001');

        self::assertSame('PNOEE-40504040001', (string) $identity);
        self::assertSame('PNO', $identity->identityType);
        self::assertSame('EE', $identity->country);

        $parsed = SemanticsIdentifier::parse('PNOEE-40504040001');
        self::assertSame((string) $identity, (string) $parsed);
    }

    public function testALatvianIdentityNumberKeepsItsHyphen(): void
    {
        $identity = SemanticsIdentifier::parse('PNOLV-050405-10009');

        self::assertSame('050405-10009', $identity->identityNumber);
        self::assertSame('LV', $identity->country);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function badIdentifiers(): iterable
    {
        yield 'no type' => ['EE-40504040001'];
        yield 'unknown type' => ['XXXEE-40504040001'];
        yield 'lower-case country' => ['PNOee-40504040001'];
        yield 'no number' => ['PNOEE-'];
        yield 'no hyphen' => ['PNOEE40504040001'];
    }

    #[DataProvider('badIdentifiers')]
    public function testAMalformedSemanticsIdentifierIsRefused(string $identifier): void
    {
        $this->expectException(InvalidArgumentException::class);

        SemanticsIdentifier::parse($identifier);
    }

    // --- document number ----------------------------------------------------

    /**
     * The middle segment varies across the demo accounts, so only the shape is
     * checked.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function documentNumbers(): iterable
    {
        yield 'mock' => ['PNOEE-40504040001-MOCK-Q', 'PNOEE-40504040001'];
        yield 'demo' => ['PNOEE-50001029996-DEMO-Q', 'PNOEE-50001029996'];
        yield 'a zero in DEM0' => ['PNOLV-050405-10009-DEM0-Q', 'PNOLV-050405-10009'];
        yield 'numbered' => ['PNOEE-40504040001-DEM2-Q', 'PNOEE-40504040001'];
        yield 'not qualified' => ['PNOLT-40504049999-MOCK-NQ', 'PNOLT-40504049999'];
        yield 'latvian with hyphen' => ['PNOLV-320000-10003-DEMO-Q', 'PNOLV-320000-10003'];
    }

    #[DataProvider('documentNumbers')]
    public function testADocumentNumberNamesThePersonInsideIt(string $value, string $expectedIdentity): void
    {
        $documentNumber = new DocumentNumber($value);

        self::assertSame($value, (string) $documentNumber);
        self::assertSame($expectedIdentity, (string) $documentNumber->semanticsIdentifier());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function badDocumentNumbers(): iterable
    {
        yield 'a semantics identifier' => ['PNOEE-40504040001'];
        yield 'too few parts' => ['PNOEE-40504040001-Q'];
        yield 'empty' => [''];
        yield 'no prefix' => ['40504040001-MOCK-Q'];
    }

    #[DataProvider('badDocumentNumbers')]
    public function testAMalformedDocumentNumberIsRefused(string $value): void
    {
        $this->expectException(InvalidArgumentException::class);

        new DocumentNumber($value);
    }

    // --- interactions -------------------------------------------------------

    public function testInteractionsEncodeAsBase64Json(): void
    {
        $interactions = Interactions::of(
            Interaction::confirmationMessage('Please sign the lease'),
            Interaction::displayTextAndPin('Sign the lease'),
        );

        $json = base64_decode($interactions->encoded, true);
        self::assertIsString($json);
        self::assertSame(
            '[{"type":"confirmationMessage","displayText200":"Please sign the lease"},{"type":"displayTextAndPIN","displayText60":"Sign the lease"}]',
            $json,
        );
        self::assertSame(base64_encode(hash('sha256', $interactions->encoded, true)), $interactions->digest());
    }

    /**
     * The digest is taken over the string that was sent, so restoring a session
     * must not re-encode it.
     */
    public function testRestoringInteractionsKeepsTheExactStringThatWasSent(): void
    {
        $original = Interactions::of(Interaction::displayTextAndPin('Tere'));
        $restored = Interactions::fromEncoded($original->encoded);

        self::assertSame($original->encoded, $restored->encoded);
        self::assertSame($original->digest(), $restored->digest());
        self::assertSame('Tere', $restored->interactions[0]->text);
    }

    public function testInteractionsNeedAtLeastOneEntry(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Interactions::of();
    }

    /**
     * @return iterable<string, array{InteractionType, int}>
     */
    public static function interactionLimits(): iterable
    {
        yield 'display text and PIN' => [InteractionType::DisplayTextAndPin, 60];
        yield 'confirmation message' => [InteractionType::ConfirmationMessage, 200];
        yield 'with code choice' => [InteractionType::ConfirmationMessageAndVerificationCodeChoice, 200];
    }

    #[DataProvider('interactionLimits')]
    public function testInteractionTextIsLimitedInCharacters(InteractionType $type, int $limit): void
    {
        self::assertSame($limit, $type->maximumLength());

        // Accented characters cost one, not two: the limit is in characters.
        new Interaction($type, str_repeat('õ', $limit));

        $this->expectException(InvalidArgumentException::class);
        new Interaction($type, str_repeat('a', $limit + 1));
    }

    public function testInteractionTextMustNotBeEmpty(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Interaction::displayTextAndPin('');
    }

    /**
     * Device-link flows have no code to compare, so the app cannot offer a
     * choice of codes.
     */
    public function testTheVerificationCodeChoiceIsDroppedForDeviceLinks(): void
    {
        $interactions = Interactions::of(
            Interaction::confirmationMessageAndVerificationCodeChoice('Sign?'),
            Interaction::displayTextAndPin('Sign?'),
        );

        $forDeviceLink = $interactions->forDeviceLink();

        self::assertCount(1, $forDeviceLink->interactions);
        self::assertSame(InteractionType::DisplayTextAndPin, $forDeviceLink->interactions[0]->type);
    }

    public function testADeviceLinkNeedsAnInteractionItCanShow(): void
    {
        $this->expectExceptionMessageMatches('/cannot show a verification-code choice/');

        Interactions::of(Interaction::confirmationMessageAndVerificationCodeChoice('Sign?'))->forDeviceLink();
    }

    // --- certificate levels -------------------------------------------------

    public function testQscdAndQualifiedSatisfyEachOther(): void
    {
        // The service answers a QSCD request with a certificate it reports as
        // QUALIFIED, so requiring QSCD must not reject its own answer.
        self::assertTrue(CertificateLevel::Qscd->isSatisfiedBy(CertificateLevel::Qualified));
        self::assertTrue(CertificateLevel::Qualified->isSatisfiedBy(CertificateLevel::Qscd));
        self::assertTrue(CertificateLevel::Advanced->isSatisfiedBy(CertificateLevel::Qualified));
        self::assertFalse(CertificateLevel::Qualified->isSatisfiedBy(CertificateLevel::Advanced));
    }

    // --- PSS parameters -----------------------------------------------------

    /**
     * @return iterable<string, array{HashAlgorithm, SignatureAlgorithm}>
     */
    public static function pssHashes(): iterable
    {
        yield 'sha256' => [HashAlgorithm::SHA256, SignatureAlgorithm::PS256];
        yield 'sha384' => [HashAlgorithm::SHA384, SignatureAlgorithm::PS384];
        yield 'sha512' => [HashAlgorithm::SHA512, SignatureAlgorithm::PS512];
    }

    #[DataProvider('pssHashes')]
    public function testTheProfileSkUsesIsTheOneRfc6931Describes(HashAlgorithm $hash, SignatureAlgorithm $expected): void
    {
        $parameters = new RsaPssParameters($hash, $hash, $hash->digestLength(), '0xbc');

        self::assertTrue($parameters->isRfc6931Profile());
        self::assertNull($parameters->complaint());
        self::assertSame($expected, $parameters->signatureAlgorithm());
    }

    /**
     * @return iterable<string, array{RsaPssParameters, string}>
     */
    public static function unusablePssParameters(): iterable
    {
        yield 'salt too short' => [new RsaPssParameters(HashAlgorithm::SHA256, HashAlgorithm::SHA256, 20, '0xbc'), 'salt is 20 bytes'];
        yield 'mask hash differs' => [new RsaPssParameters(HashAlgorithm::SHA256, HashAlgorithm::SHA512, 32, '0xbc'), 'mask generation function uses SHA-512'];
        yield 'wrong trailer' => [new RsaPssParameters(HashAlgorithm::SHA256, HashAlgorithm::SHA256, 32, '0x01'), 'trailer field is 0x01'];
    }

    #[DataProvider('unusablePssParameters')]
    public function testParametersNoXmlDsigMethodDescribesAreRejected(RsaPssParameters $parameters, string $expectedComplaint): void
    {
        self::assertFalse($parameters->isRfc6931Profile());
        self::assertStringContainsString($expectedComplaint, (string) $parameters->complaint());
    }

    // --- configuration ------------------------------------------------------

    public function testDemoConfigurationIsRecognisable(): void
    {
        $configuration = SmartIdConfiguration::demo();

        self::assertTrue($configuration->isDemo());
        self::assertSame(SmartIdConfiguration::SCHEME_DEMO, $configuration->scheme);
        // The signed payload carries the name base64-encoded.
        self::assertSame('REVNTw==', $configuration->relyingPartyNameBase64());
        self::assertFalse(SmartIdConfiguration::production('11111111-2222-3333-4444-555555555555', 'Allkiri')->isDemo());
    }

    public function testTheSchemeMustBeOneTheProtocolKnows(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new SmartIdConfiguration(SmartIdConfiguration::DEMO_URL, SmartIdConfiguration::DEMO_RELYING_PARTY_UUID, 'DEMO', 'smart-id-staging');
    }

    /**
     * Every request carries the relying-party identifier, and most name the
     * person being asked for.
     */
    public function testAServiceUrlThatIsNotHttpsIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The Smart-ID service URL must be an https:// URL');

        new SmartIdConfiguration('http://sid.demo.sk.ee/smart-id-rp/v3', SmartIdConfiguration::DEMO_RELYING_PARTY_UUID, 'DEMO', SmartIdConfiguration::SCHEME_DEMO);
    }

    public function testARelyingPartyNameLongerThanTheServiceAllowsIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);

        SmartIdConfiguration::production('11111111-2222-3333-4444-555555555555', str_repeat('a', 33));
    }

    public function testHttpTimeoutLeavesRoomForTheLongPoll(): void
    {
        self::assertSame(15, SmartIdConfiguration::demo()->httpTimeoutSeconds());
        self::assertSame(125, SmartIdConfiguration::demo()->withTimeouts(120_000, 300)->httpTimeoutSeconds());
    }

    // --- end results --------------------------------------------------------

    public function testEveryEndResultHasAMessage(): void
    {
        foreach (SmartIdEndResult::cases() as $result) {
            self::assertNotSame('', $result->message(), $result->value . ' has no message');
        }
    }

    public function testABlockedAccountIsNotWorthRetrying(): void
    {
        self::assertFalse(SmartIdEndResult::DocumentUnusable->isWorthRetrying());
        self::assertFalse(SmartIdEndResult::AccountUnusable->isWorthRetrying());
        self::assertFalse(SmartIdEndResult::RequiredInteractionNotSupportedByApp->isWorthRetrying());
        self::assertTrue(SmartIdEndResult::UserRefused->isWorthRetrying());
        self::assertTrue(SmartIdEndResult::Timeout->isWorthRetrying());
    }
}
