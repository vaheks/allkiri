<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\SmartId;

use Allkiri\Crypto\HashAlgorithm;
use Allkiri\SmartId\AcspV2Payload;
use Allkiri\SmartId\CertificateLevel;
use Allkiri\SmartId\DeviceLink;
use Allkiri\SmartId\DocumentNumber;
use Allkiri\SmartId\FlowType;
use Allkiri\SmartId\Interaction;
use Allkiri\SmartId\Interactions;
use Allkiri\SmartId\InteractionType;
use Allkiri\SmartId\SemanticsIdentifier;
use Allkiri\SmartId\SmartIdAuthenticator;
use Allkiri\SmartId\SmartIdClient;
use Allkiri\SmartId\SmartIdEndResult;
use Allkiri\SmartId\SmartIdException;
use Allkiri\SmartId\SmartIdPoller;
use Allkiri\SmartId\SmartIdSession;
use Allkiri\SmartId\SmartIdSessionException;
use Allkiri\SmartId\SmartIdSessionStatus;
use Allkiri\SmartId\VerificationCode;
use Allkiri\Tests\Support\Clock\FrozenClock;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Tests\Support\MobileId\NullSleeper;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Tests\Support\SmartId\MockSmartIdService;
use Allkiri\Trust\ChainBuilder;
use Allkiri\Trust\InMemoryTrustStore;
use Allkiri\Trust\ServiceType;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class SmartIdAuthenticatorTest extends TestCase
{
    /** The identity in the test PKI's personal RSA certificate. */
    private const IDENTITY_CODE = '40504040001';

    private FrozenClock $clock;

    private MockHttpClient $http;

    private MockSmartIdService $service;

    private SmartIdClient $client;

    protected function setUp(): void
    {
        $this->clock = new FrozenClock('2026-03-01T10:00:00Z');
        $this->http = new MockHttpClient();
        $this->service = MockSmartIdService::register($this->http);
        $this->client = new SmartIdClient($this->service->configuration(), $this->http);
    }

    private function authenticator(?ChainBuilder $chainBuilder = null): SmartIdAuthenticator
    {
        return new SmartIdAuthenticator($this->client, $chainBuilder, clock: $this->clock);
    }

    private function trustedChainBuilder(): ChainBuilder
    {
        return new ChainBuilder(InMemoryTrustStore::fromCertificates([TestPki::ca()->certificate], ServiceType::CaQc, 'test PKI'));
    }

    private static function identity(): SemanticsIdentifier
    {
        return SemanticsIdentifier::estonian(self::IDENTITY_CODE);
    }

    private static function interactions(): Interactions
    {
        return Interactions::of(Interaction::displayTextAndPin('Log in to allkiri'));
    }

    // --- notification flow --------------------------------------------------

    public function testANotificationSessionCarriesTheCodeTheServiceReturned(): void
    {
        $session = $this->authenticator()->startNotification(self::identity(), self::interactions());

        self::assertSame(SmartIdSession::TYPE_AUTHENTICATION, $session->type);
        self::assertMatchesRegularExpression('/^\d{4}$/', (string) $session->verificationCode);
        // The service derives it from the challenge, so it must agree.
        self::assertSame(VerificationCode::forData($session->challenge), $session->verificationCode);
        self::assertFalse($session->isDeviceLink());
    }

    public function testTheChallengeIsSixtyFourRandomBytesAndIsSentBase64(): void
    {
        $authenticator = $this->authenticator();
        $first = $authenticator->startNotification(self::identity(), self::interactions());
        $second = $authenticator->startNotification(self::identity(), self::interactions());

        self::assertSame(64, \strlen($first->challenge));
        self::assertNotSame($first->challenge, $second->challenge);

        $body = $this->service->lastRequestTo('/authentication/notification');
        $parameters = $body['signatureProtocolParameters'];
        self::assertIsArray($parameters);
        self::assertSame(base64_encode($second->challenge), $parameters['rpChallenge']);
        self::assertSame('rsassa-pss', $parameters['signatureAlgorithm']);
    }

    public function testASuccessfulAuthenticationNamesThePerson(): void
    {
        $authenticator = $this->authenticator($this->trustedChainBuilder());
        $session = $authenticator->startNotification(self::identity(), self::interactions());

        $identity = $authenticator->poll($session);

        self::assertNotNull($identity);
        self::assertSame(self::IDENTITY_CODE, $identity->identityCode);
        self::assertSame('EE', $identity->country);
        self::assertSame('PNOEE-' . self::IDENTITY_CODE, $identity->semanticsIdentifier());
        // The new certificate profile puts the given name first in the common
        // name, so these must come from the SN and GN attributes.
        self::assertSame('MARY ANN', $identity->givenName);
        self::assertSame('OCONNEZ-SUSLIK TESTNUMBER', $identity->surname);
    }

    public function testPollingReturnsNullWhileThePersonIsStillDeciding(): void
    {
        $this->service->runningPolls = 1;
        $authenticator = $this->authenticator();
        $session = $authenticator->startNotification(self::identity(), self::interactions());

        self::assertNull($authenticator->poll($session));
        self::assertNotNull($authenticator->poll($session));
    }

    public function testBlockingAuthenticationWaitsForThePerson(): void
    {
        $this->service->runningPolls = 3;
        $authenticator = $this->authenticator($this->trustedChainBuilder());
        $session = $authenticator->startNotification(self::identity(), self::interactions());

        $identity = $authenticator->authenticate($session, new SmartIdPoller($this->client, new NullSleeper()));

        self::assertSame(self::IDENTITY_CODE, $identity->identityCode);
    }

    public function testADocumentNumberMayBeUsedInsteadOfAPerson(): void
    {
        $authenticator = $this->authenticator();
        $documentNumber = new DocumentNumber(MockSmartIdService::DOCUMENT_NUMBER);

        $session = $authenticator->startNotification($documentNumber, self::interactions());

        self::assertSame(MockSmartIdService::DOCUMENT_NUMBER, $session->documentNumber);
        self::assertStringContainsString('/document/', $this->service->received[0]['path']);
    }

    // --- device-link flow ---------------------------------------------------

    public function testAnAnonymousSessionYieldsALinkAndItsOwnCode(): void
    {
        $this->service->flowType = FlowType::Qr;
        $authenticator = $this->authenticator($this->trustedChainBuilder());

        $session = $authenticator->startAnonymous(self::interactions());

        self::assertTrue($session->isDeviceLink());
        self::assertNotNull($session->sessionSecret);
        // Nothing was pushed, so the code comes from the challenge.
        self::assertSame(VerificationCode::forData($session->challenge), $session->verificationCode);

        $configuration = $this->service->configuration();
        $link = $session->deviceLink($configuration->scheme, $configuration->relyingPartyNameBase64());
        $url = $link->url($session->sessionSecret, 0);

        self::assertStringContainsString('deviceLinkType=QR', $url);
        self::assertStringContainsString('sessionType=auth', $url);
        self::assertStringContainsString('authCode=', $url);
    }

    public function testADeviceLinkAuthenticationVerifiesWithTheUserChallenge(): void
    {
        $this->service->flowType = FlowType::Web2App;
        $authenticator = $this->authenticator($this->trustedChainBuilder());
        $session = $authenticator->startDeviceLink(self::identity(), self::interactions());

        // The mock derives the user challenge from this verifier, the way an
        // app and a callback URL would.
        $verifier = 'user-challenge-' . $session->challenge;
        $identity = $authenticator->poll($session, $verifier);

        self::assertNotNull($identity);
        self::assertSame(self::IDENTITY_CODE, $identity->identityCode);
    }

    public function testAUserChallengeVerifierFromAnotherSessionIsRefused(): void
    {
        $this->service->flowType = FlowType::Web2App;
        $authenticator = $this->authenticator();
        $session = $authenticator->startDeviceLink(self::identity(), self::interactions());

        $this->expectExceptionMessageMatches('/verifier from the callback does not match/');

        $authenticator->poll($session, 'user-challenge-from-somewhere-else');
    }

    public function testTheVerificationCodeChoiceIsNotOfferedOnADeviceLink(): void
    {
        $authenticator = $this->authenticator();
        $interactions = Interactions::of(
            Interaction::confirmationMessageAndVerificationCodeChoice('Log in?'),
            Interaction::displayTextAndPin('Log in?'),
        );

        $session = $authenticator->startAnonymous($interactions);

        self::assertCount(1, $session->interactions->interactions);
        self::assertSame(InteractionType::DisplayTextAndPin, $session->interactions->interactions[0]->type);
    }

    // --- what the signature actually covers ---------------------------------

    /**
     * The payload names the scheme, so a signature made for the demo service
     * cannot be replayed against production or the reverse.
     */
    public function testTheSchemeIsPartOfWhatIsSigned(): void
    {
        $authenticator = $this->authenticator();
        $session = $authenticator->startNotification(self::identity(), self::interactions());
        $status = $this->client->sessionStatus($session->sessionId);

        $production = $this->service->configuration();
        $productionClient = new SmartIdClient(
            new \Allkiri\SmartId\SmartIdConfiguration($production->url, $production->relyingPartyUuid, $production->relyingPartyName, \Allkiri\SmartId\SmartIdConfiguration::SCHEME_PRODUCTION),
            $this->http,
        );

        $this->expectExceptionMessageMatches('/does not match this session/');

        (new SmartIdAuthenticator($productionClient, null, clock: $this->clock))->complete($session, $status);
    }

    /**
     * The interaction list is signed as a digest, so an answer cannot be
     * re-used against a session that offered different dialogues.
     */
    public function testTheInteractionsArePartOfWhatIsSigned(): void
    {
        $authenticator = $this->authenticator();
        $session = $authenticator->startNotification(self::identity(), self::interactions());
        $status = $this->client->sessionStatus($session->sessionId);

        $substituted = new SmartIdSession(
            $session->sessionId,
            $session->type,
            $session->challenge,
            Interactions::of(Interaction::displayTextAndPin('Something else entirely')),
            $session->verificationCode,
        );

        $this->expectExceptionMessageMatches('/does not match this session/');

        $authenticator->complete($substituted, $status);
    }

    public function testTheChallengeIsPartOfWhatIsSigned(): void
    {
        $authenticator = $this->authenticator();
        $session = $authenticator->startNotification(self::identity(), self::interactions());
        $status = $this->client->sessionStatus($session->sessionId);

        $substituted = new SmartIdSession(
            $session->sessionId,
            $session->type,
            random_bytes(64),
            $session->interactions,
            $session->verificationCode,
        );

        $this->expectExceptionMessageMatches('/does not match this session/');

        $authenticator->complete($substituted, $status);
    }

    /**
     * The eleven parts of the payload, in the order the protocol fixes.
     */
    public function testThePayloadHasElevenPartsWithAReservedEmptyOne(): void
    {
        $payload = new AcspV2Payload(
            'smart-id-demo',
            base64_encode('server'),
            base64_encode('challenge'),
            'user-challenge',
            base64_encode('DEMO'),
            null,
            'digest',
            InteractionType::DisplayTextAndPin,
            FlowType::Qr,
        );

        $parts = explode('|', $payload->bytes());

        self::assertCount(11, $parts);
        self::assertSame('smart-id-demo', $parts[0]);
        self::assertSame('ACSP_V2', $parts[1]);
        self::assertSame(base64_encode('server'), $parts[2]);
        self::assertSame(base64_encode('challenge'), $parts[3]);
        self::assertSame('user-challenge', $parts[4]);
        self::assertSame(base64_encode('DEMO'), $parts[5]);
        self::assertSame('', $parts[6], 'no brokered relying party');
        self::assertSame('digest', $parts[7]);
        self::assertSame('displayTextAndPIN', $parts[8]);
        self::assertSame('', $parts[9], 'the tenth part is reserved and empty');
        self::assertSame('QR', $parts[10]);
    }

    // --- refusals -----------------------------------------------------------

    public function testACorruptSignatureIsRefused(): void
    {
        $this->service->corruptSignature = true;
        $authenticator = $this->authenticator();
        $session = $authenticator->startNotification(self::identity(), self::interactions());

        $this->expectExceptionMessageMatches('/does not match this session/');

        $authenticator->poll($session);
    }

    /**
     * @return iterable<string, array{SmartIdEndResult}>
     */
    public static function refusals(): iterable
    {
        yield 'cancelled' => [SmartIdEndResult::UserRefused];
        yield 'timed out' => [SmartIdEndResult::Timeout];
        yield 'wrong code chosen' => [SmartIdEndResult::WrongVerificationCode];
        yield 'account unusable' => [SmartIdEndResult::DocumentUnusable];
        yield 'app too old' => [SmartIdEndResult::RequiredInteractionNotSupportedByApp];
        yield 'protocol failure' => [SmartIdEndResult::ProtocolFailure];
    }

    #[DataProvider('refusals')]
    public function testEveryRefusalArrivesAsItself(SmartIdEndResult $expected): void
    {
        $this->service->endResult = $expected;
        $authenticator = $this->authenticator();
        $session = $authenticator->startNotification(self::identity(), self::interactions());

        try {
            $authenticator->poll($session);
            self::fail('Expected a SmartIdSessionException');
        } catch (SmartIdSessionException $exception) {
            self::assertSame($expected, $exception->result);
            self::assertStringContainsString($expected->message(), $exception->getMessage());
        }
    }

    public function testARefusedDialogueIsNamed(): void
    {
        $this->service->endResult = SmartIdEndResult::UserRefusedInteraction;
        $this->service->refusedInteraction = InteractionType::ConfirmationMessage;
        $authenticator = $this->authenticator();
        $session = $authenticator->startNotification(self::identity(), self::interactions());

        try {
            $authenticator->poll($session);
            self::fail('Expected a SmartIdSessionException');
        } catch (SmartIdSessionException $exception) {
            self::assertSame(InteractionType::ConfirmationMessage, $exception->refusedInteraction);
            self::assertStringContainsString('confirmationMessage', $exception->getMessage());
        }
    }

    /**
     * @return iterable<string, array{\Closure(MockSmartIdService): void, string}>
     */
    public static function unusableParameters(): iterable
    {
        yield 'salt of the wrong length' => [
            static function (MockSmartIdService $service): void {
                $service->saltLengthOverride = 20;
            },
            'salt is 20 bytes',
        ];
        yield 'mask over another hash' => [
            static function (MockSmartIdService $service): void {
                $service->maskHashOverride = HashAlgorithm::SHA512;
            },
            'mask generation function',
        ];
        yield 'wrong trailer field' => [
            static function (MockSmartIdService $service): void {
                $service->trailerFieldOverride = '0x01';
            },
            'trailer field',
        ];
    }

    #[DataProvider('unusableParameters')]
    public function testPssParametersOutsideTheProfileAreRefused(\Closure $configure, string $expected): void
    {
        $configure($this->service);
        $authenticator = $this->authenticator();
        $session = $authenticator->startNotification(self::identity(), self::interactions());

        $this->expectExceptionMessageMatches('/' . preg_quote($expected, '/') . '/');

        $authenticator->poll($session);
    }

    public function testALegacyPkcs1AnswerIsRefusedForAuthentication(): void
    {
        $this->service->legacyRsa = true;
        $authenticator = $this->authenticator();
        $session = $authenticator->startNotification(self::identity(), self::interactions());

        $this->expectExceptionMessageMatches('/signature algorithm this library does not accept/');

        $authenticator->poll($session);
    }

    public function testACertificateWeakerThanRequestedIsRefused(): void
    {
        $this->service->certificateLevel = CertificateLevel::Advanced;
        $authenticator = $this->authenticator();
        $session = $authenticator->startNotification(self::identity(), self::interactions());

        $this->expectExceptionMessageMatches('/ADVANCED certificate where QUALIFIED was requested/');

        $authenticator->poll($session);
    }

    public function testACertificateFromAnUnknownAuthorityIsRefused(): void
    {
        $authenticator = $this->authenticator(new ChainBuilder(new InMemoryTrustStore([])));
        $session = $authenticator->startNotification(self::identity(), self::interactions());

        $this->expectExceptionMessageMatches('/does not chain to a trusted authority/');

        $authenticator->poll($session);
    }

    public function testACertificateOutsideItsValidityIsRefused(): void
    {
        $this->clock->set('2060-01-01T00:00:00Z');
        $authenticator = $this->authenticator();
        $session = $authenticator->startNotification(self::identity(), self::interactions());

        $this->expectExceptionMessageMatches('/not valid at this moment/');

        $authenticator->poll($session);
    }

    /**
     * The parser tolerates a session that signed nothing, because a certificate
     * choice looks like that. An authentication must not.
     */
    public function testAnAuthenticationWithoutASignatureIsRefused(): void
    {
        $authenticator = $this->authenticator();
        $session = $authenticator->startNotification(self::identity(), self::interactions());

        $status = new SmartIdSessionStatus(
            SmartIdSessionStatus::STATE_COMPLETE,
            SmartIdEndResult::Ok,
            new DocumentNumber(MockSmartIdService::DOCUMENT_NUMBER),
            certificate: $this->service->certificate(),
            certificateLevel: CertificateLevel::Qualified,
            signatureProtocol: AcspV2Payload::PROTOCOL,
            interactionTypeUsed: InteractionType::DisplayTextAndPin,
        );

        $this->expectExceptionMessageMatches('/does not accept for authentication/');

        $authenticator->complete($session, $status);
    }

    public function testAnAuthenticationWithoutACertificateIsRefused(): void
    {
        $authenticator = $this->authenticator();
        $session = $authenticator->startNotification(self::identity(), self::interactions());

        $status = new SmartIdSessionStatus(
            SmartIdSessionStatus::STATE_COMPLETE,
            SmartIdEndResult::Ok,
            new DocumentNumber(MockSmartIdService::DOCUMENT_NUMBER),
            signatureProtocol: AcspV2Payload::PROTOCOL,
        );

        $this->expectExceptionMessageMatches('/without returning a certificate/');

        $authenticator->complete($session, $status);
    }

    public function testASigningSessionCannotBeCompletedAsAnAuthentication(): void
    {
        $authenticator = $this->authenticator();
        $session = $authenticator->startNotification(self::identity(), self::interactions());
        $status = $this->client->sessionStatus($session->sessionId);

        $signing = new SmartIdSession($session->sessionId, SmartIdSession::TYPE_SIGNATURE, $session->challenge, $session->interactions);

        $this->expectException(SmartIdException::class);

        $authenticator->complete($signing, $status);
    }

    // --- session storage ----------------------------------------------------

    public function testASessionSurvivesJsonBetweenTwoRequests(): void
    {
        $this->service->flowType = FlowType::Qr;
        $authenticator = $this->authenticator($this->trustedChainBuilder());
        $session = $authenticator->startAnonymous(self::interactions());

        $restored = SmartIdSession::fromJson(json_encode($session, JSON_THROW_ON_ERROR));

        self::assertSame($session->sessionId, $restored->sessionId);
        self::assertSame($session->challenge, $restored->challenge);
        self::assertSame($session->interactions->encoded, $restored->interactions->encoded);
        self::assertSame($session->sessionSecret, $restored->sessionSecret);
        self::assertSame($session->sessionToken, $restored->sessionToken);

        // And it still verifies, which is the point of keeping it.
        self::assertNotNull($authenticator->poll($restored, 'user-challenge-' . $restored->challenge));
    }

    public function testADeviceLinkBuiltFromARestoredSessionIsIdentical(): void
    {
        $this->service->flowType = FlowType::Qr;
        $session = $this->authenticator()->startAnonymous(self::interactions());
        $restored = SmartIdSession::fromJson(json_encode($session, JSON_THROW_ON_ERROR));
        $configuration = $this->service->configuration();

        self::assertNotNull($session->sessionSecret);
        self::assertSame(
            $session->deviceLink($configuration->scheme, $configuration->relyingPartyNameBase64())->url($session->sessionSecret, 3),
            $restored->deviceLink($configuration->scheme, $configuration->relyingPartyNameBase64())->url($session->sessionSecret, 3),
        );
    }

    public function testTheBase64UrlHelperMatchesTheProtocol(): void
    {
        // No padding, and the two substituted characters.
        self::assertSame('_w', DeviceLink::base64Url("\xff"));
        self::assertSame('-_8', DeviceLink::base64Url("\xfb\xff"));
    }
}
