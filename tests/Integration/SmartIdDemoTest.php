<?php

declare(strict_types=1);

namespace Allkiri\Tests\Integration;

use Allkiri\Allkiri;
use Allkiri\Clock\SystemClock;
use Allkiri\Config\Environment;
use Allkiri\Container\AsicContainer;
use Allkiri\Container\AsicWriter;
use Allkiri\Container\DataFile;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Http\HttpRequest;
use Allkiri\Signing\SignatureLevel;
use Allkiri\SmartId\CertificateLevel;
use Allkiri\SmartId\DeviceLink;
use Allkiri\SmartId\DocumentNumber;
use Allkiri\SmartId\FlowType;
use Allkiri\SmartId\Interaction;
use Allkiri\SmartId\Interactions;
use Allkiri\SmartId\SmartIdApiException;
use Allkiri\SmartId\SmartIdCallback;
use Allkiri\SmartId\SmartIdConfiguration;
use Allkiri\SmartId\SmartIdEndResult;
use Allkiri\SmartId\SmartIdException;
use Allkiri\SmartId\SmartIdPoller;
use Allkiri\SmartId\SmartIdSession;
use Allkiri\SmartId\SmartIdSessionException;
use Allkiri\Validation\Report\Indication;
use Allkiri\Validation\Siva\SivaClient;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Smart-ID against SK's demo service, using their published test accounts.
 *
 * Notification flows answer by themselves. A device-link flow needs someone to
 * scan the code or tap the link, and SK's demo service has a stand-in for that
 * person: its mock scan, which takes the link and a test account and ends the
 * session as that account would.
 */
final class SmartIdDemoTest extends IntegrationTestCase
{
    /** An adult account that answers OK. */
    private const OK_DOCUMENT = 'PNOEE-50001029996-DEMO-Q';

    /** Issued under TEST of SK ID Solutions EID-Q 2024E. */
    private const OK_DOCUMENT_2024 = 'PNOEE-40504040001-DEM2-Q';

    /** An adult account that answers OK to a device link handed to the mock scan. */
    private const MOCK_DOCUMENT = 'PNOEE-40404040009-MOCK-Q';

    /** SK's stand-in for a person with a phone, beside the demo service only. */
    private const MOCK_SCAN_URL = 'https://sid.demo.sk.ee/mock/device-link';

    private function configuration(): SmartIdConfiguration
    {
        return new SmartIdConfiguration(
            self::env('ALLKIRI_SMARTID_URL', SmartIdConfiguration::DEMO_URL),
            self::env('ALLKIRI_SMARTID_RP_UUID', SmartIdConfiguration::DEMO_RELYING_PARTY_UUID),
            self::env('ALLKIRI_SMARTID_RP_NAME', SmartIdConfiguration::DEMO_RELYING_PARTY_NAME),
            SmartIdConfiguration::SCHEME_DEMO,
            CertificateLevel::Qualified,
            sessionTimeoutSeconds: 90,
        );
    }

    private function allkiri(): Allkiri
    {
        $configuration = $this->configuration();

        return new Allkiri(Environment::demo(), self::http($configuration->httpTimeoutSeconds()), new SystemClock());
    }

    private static function interactions(): Interactions
    {
        return Interactions::of(Interaction::confirmationMessage('allkiri integration test'));
    }

    // --- certificates -------------------------------------------------------

    public function testACertificateCanBeFetchedWithNoInteraction(): void
    {
        $client = $this->allkiri()->smartIdClient($this->configuration());

        $certificate = $client->certificateByDocumentNumber(new DocumentNumber(self::OK_DOCUMENT));

        self::assertStringContainsString('50001029996', $certificate->certificate->subjectDn());
        self::assertTrue($certificate->certificate->isValidAt(new \DateTimeImmutable()));
        // Smart-ID keys are RSA throughout.
        self::assertSame('RSA', $certificate->certificate->keyType()->name);
        self::assertGreaterThanOrEqual(2048, $certificate->certificate->keyBits());
    }

    public function testAnUnknownAccountIsReportedAsSuch(): void
    {
        $client = $this->allkiri()->smartIdClient($this->configuration());

        try {
            $client->certificateByDocumentNumber(new DocumentNumber('PNOEE-00000000000-MOCK-Q'));
            self::fail('Expected a SmartIdApiException');
        } catch (SmartIdApiException $exception) {
            self::assertContains($exception->reason, [
                SmartIdApiException::REASON_ACCOUNT_NOT_FOUND,
                SmartIdApiException::REASON_NO_SUITABLE_ACCOUNT,
            ], $exception->getMessage());
        }
    }

    // --- authentication -----------------------------------------------------

    public function testAuthenticatingWithADemoAccountNamesThePerson(): void
    {
        $configuration = $this->configuration();
        $allkiri = $this->allkiri();
        $authenticator = $allkiri->smartIdAuthenticator($configuration);

        $session = $authenticator->startNotification(new DocumentNumber(self::OK_DOCUMENT), self::interactions());
        self::assertMatchesRegularExpression('/^\d{4}$/', (string) $session->verificationCode);

        $identity = $authenticator->authenticate($session, new SmartIdPoller($allkiri->smartIdClient($configuration)));

        self::assertSame('50001029996', $identity->identityCode);
        self::assertSame('EE', $identity->country);
        self::assertNotSame('', $identity->surname);
        self::assertNotSame('', $identity->givenName);
        self::assertSame('PNOEE-50001029996', $identity->semanticsIdentifier());
    }

    /**
     * A person can be addressed without knowing which of their accounts will
     * answer; the session reports the one that did.
     */
    public function testAuthenticatingByPersonRatherThanAccountAlsoWorks(): void
    {
        $configuration = $this->configuration();
        $allkiri = $this->allkiri();
        $authenticator = $allkiri->smartIdAuthenticator($configuration);

        $session = $authenticator->startNotification(
            (new DocumentNumber(self::OK_DOCUMENT))->semanticsIdentifier(),
            self::interactions(),
        );
        $status = (new SmartIdPoller($allkiri->smartIdClient($configuration)))->wait($session);

        self::assertTrue($status->isOk(), (string) $status->result?->value);
        self::assertSame(self::OK_DOCUMENT, $status->documentNumber?->value);

        $identity = $authenticator->complete($session, $status);
        self::assertSame('50001029996', $identity->identityCode);
    }

    // --- every published refusal --------------------------------------------

    /**
     * SK's published accounts, each documented to end one way.
     *
     * @return iterable<string, array{string, SmartIdEndResult}>
     */
    public static function refusingAccounts(): iterable
    {
        yield 'user refuses' => ['PNOEE-30403039917-MOCK-Q', SmartIdEndResult::UserRefused];
        yield 'user refuses the dialogue' => ['PNOEE-30403039946-MOCK-Q', SmartIdEndResult::UserRefusedInteraction];
        yield 'wrong verification code chosen' => ['PNOEE-30403039972-MOCK-Q', SmartIdEndResult::WrongVerificationCode];
        yield 'user does not react' => ['PNOEE-30403039983-MOCK-Q', SmartIdEndResult::Timeout];
    }

    #[DataProvider('refusingAccounts')]
    public function testEveryPublishedRefusalArrivesAsItsOwnResult(string $documentNumber, SmartIdEndResult $expected): void
    {
        $configuration = $this->configuration();
        $allkiri = $this->allkiri();
        $authenticator = $allkiri->smartIdAuthenticator($configuration);

        $session = $authenticator->startNotification(new DocumentNumber($documentNumber), self::interactions());

        try {
            (new SmartIdPoller($allkiri->smartIdClient($configuration)))->waitForSuccess($session);
            self::fail(\sprintf('%s was expected to end with %s', $documentNumber, $expected->value));
        } catch (SmartIdSessionException $exception) {
            self::assertSame($expected, $exception->result, $exception->getMessage());
            self::assertNotSame('', $exception->result->message());
        }
    }

    // --- signing ------------------------------------------------------------

    /**
     * @return iterable<string, array{string, HashAlgorithm, SignatureAlgorithm}>
     */
    public static function signingAccounts(): iterable
    {
        yield 'SHA-256' => [self::OK_DOCUMENT, HashAlgorithm::SHA256, SignatureAlgorithm::PS256];
        yield 'SHA-512' => [self::OK_DOCUMENT, HashAlgorithm::SHA512, SignatureAlgorithm::PS512];
        yield 'EID-Q 2024E account' => [self::OK_DOCUMENT_2024, HashAlgorithm::SHA256, SignatureAlgorithm::PS256];
    }

    /**
     * The Phase 3 gate: an RSA-PSS container signed by a demo account, accepted
     * by our own validator and by RIA's SiVa.
     */
    #[DataProvider('signingAccounts')]
    public function testAnRsaPssContainerIsAcceptedEverywhere(string $documentNumber, HashAlgorithm $hash, SignatureAlgorithm $expected): void
    {
        $configuration = $this->configuration()->withSigningHashAlgorithm($hash)->withCertificateLevel(CertificateLevel::Qscd);
        $allkiri = $this->allkiri();
        $signer = $allkiri->smartIdSigner($configuration);

        $container = AsicContainer::create(DataFile::fromString(
            'allkiri.txt',
            'Smart-ID interop check ' . date(DATE_ATOM),
        ));

        $signing = $signer->startNotification($container, new DocumentNumber($documentNumber), self::interactions());
        self::assertSame($expected, $signing->dataToBeSigned->algorithm);
        self::assertMatchesRegularExpression('/^\d{4}$/', (string) $signing->verificationCode());

        $status = (new SmartIdPoller($allkiri->smartIdClient($configuration)))->wait($signing->session);
        $result = $signer->complete($container, $signing, $status);

        self::assertSame(SignatureLevel::LT, $result->level);
        self::assertNotNull($result->timestampTime);
        self::assertNotNull($result->ocspProducedAt);

        $bytes = (new AsicWriter())->write($result->container);
        self::assertAcceptedEverywhere($allkiri, $bytes);

        self::saveArtefact(\sprintf('smart-id-%s-%s.asice', $hash->name(), substr($documentNumber, 6, 11)), $bytes);
    }

    /**
     * A signing certificate for an account we do not know yet costs one
     * interaction, after which the document number needs none.
     */
    public function testACertificateChoiceYieldsADocumentNumber(): void
    {
        $configuration = $this->configuration();
        $allkiri = $this->allkiri();
        $client = $allkiri->smartIdClient($configuration);

        $sessionId = $client->startNotificationCertificateChoice(
            (new DocumentNumber(self::OK_DOCUMENT))->semanticsIdentifier(),
            CertificateLevel::Qscd,
        );

        $deadline = time() + 90;
        do {
            $status = $client->sessionStatus($sessionId);
        } while ($status->isRunning() && time() < $deadline);

        self::assertTrue($status->isComplete(), 'the certificate choice never completed');
        // Nothing was signed, so the session carries an account and a
        // certificate and no signature at all.
        self::assertNull($status->signatureValue);

        $chosen = $allkiri->smartIdSigner($configuration)->completeCertificateChoice($status, CertificateLevel::Qscd);

        self::assertSame(self::OK_DOCUMENT, $chosen->documentNumber->value);
        self::assertStringContainsString('50001029996', $chosen->certificate->subjectDn());
    }

    // --- device links, through SK's mock scan -----------------------------

    public function testAQrCodeSignInIsFinishedByTheMockScan(): void
    {
        $this->requireMockScan();
        $configuration = $this->configuration();
        $allkiri = $this->allkiri();
        $authenticator = $allkiri->smartIdAuthenticator($configuration);

        $session = $authenticator->startAnonymous(self::interactions());
        $this->scan(self::qrLink($session, $configuration), 'QR');
        $status = (new SmartIdPoller($allkiri->smartIdClient($configuration)))->wait($session);

        self::assertTrue($status->isOk(), (string) $status->result?->value);
        self::assertSame(FlowType::Qr, $status->flowType);
        $identity = $authenticator->complete($session, $status);
        self::assertSame('PNOEE-40404040009', $identity->semanticsIdentifier());
    }

    /**
     * The service checks the authentication code of every link, so a pass above
     * means it computed the same code. One changed character is enough to fail.
     */
    public function testAQrLinkWithAWrongAuthenticationCodeEndsInAProtocolFailure(): void
    {
        $this->requireMockScan();
        $configuration = $this->configuration();
        $allkiri = $this->allkiri();
        $session = $allkiri->smartIdAuthenticator($configuration)->startAnonymous(self::interactions());

        $link = self::qrLink($session, $configuration);
        $tampered = (string) preg_replace_callback('/authCode=(.)/', static fn(array $m): string => 'authCode=' . ($m[1] === 'A' ? 'B' : 'A'), $link);
        self::assertNotSame($link, $tampered);
        $this->scan($tampered, 'QR');

        $status = (new SmartIdPoller($allkiri->smartIdClient($configuration)))->wait($session);
        self::assertSame(SmartIdEndResult::ProtocolFailure, $status->result, 'a link with a wrong code must not be answered');
    }

    public function testASignatureThroughAQrCodeIsAcceptedEverywhere(): void
    {
        $this->requireMockScan();
        $configuration = $this->configuration()->withCertificateLevel(CertificateLevel::Qscd);
        $allkiri = $this->allkiri();
        $signer = $allkiri->smartIdSigner($configuration);
        $container = AsicContainer::create(DataFile::fromString('allkiri.txt', 'Smart-ID QR signing check ' . date(DATE_ATOM)));

        $signing = $signer->startDeviceLink($container, new DocumentNumber(self::MOCK_DOCUMENT), self::interactions());
        $this->scan(self::qrLink($signing->session, $configuration), 'QR');
        $result = $signer->sign($container, $signing, new SmartIdPoller($allkiri->smartIdClient($configuration)));

        self::assertSame(SignatureLevel::LT, $result->level);
        $bytes = (new AsicWriter())->write($result->container);
        self::assertAcceptedEverywhere($allkiri, $bytes);

        self::saveArtefact('smart-id-qr-' . substr(self::MOCK_DOCUMENT, 6, 11) . '.asice', $bytes);
    }

    /**
     * A tap on a Web2App link, up to where a CI runner can follow it. The mock
     * then opens the callback URL from SK's servers, which cannot reach this
     * machine, so the success path is left to a person with a phone. What can
     * be checked here: SK finishes the session through Web2App with a user
     * challenge, and the library will not accept that answer without a
     * callback that belongs to the session.
     */
    public function testAWeb2AppAnswerIsNotAcceptedWithoutItsCallback(): void
    {
        $this->requireMockScan();
        $configuration = $this->configuration();
        $allkiri = $this->allkiri();
        $authenticator = $allkiri->smartIdAuthenticator($configuration);

        // .invalid never resolves, so the mock's attempt to open it goes nowhere.
        $callbackUrl = SmartIdCallback::initialUrl('https://allkiri.invalid/smart-id/callback');
        $session = $authenticator->startAnonymous(self::interactions(), initialCallbackUrl: $callbackUrl);
        self::assertNotNull($session->sessionSecret);
        $link = $session->deviceLink($configuration->scheme, $configuration->relyingPartyNameBase64(), DeviceLink::TYPE_WEB2APP)->url($session->sessionSecret);
        $this->scan($link, 'Web2App', ['browserCookie' => 'allkiri-integration-test=1', 'initialCallbackUrl' => $callbackUrl]);

        $status = (new SmartIdPoller($allkiri->smartIdClient($configuration)))->wait($session);
        self::assertTrue($status->isOk(), (string) $status->result?->value);
        self::assertSame(FlowType::Web2App, $status->flowType);
        self::assertNotNull($status->userChallenge, 'a same-device answer carries the user challenge its callback proves');

        try {
            $authenticator->complete($session, $status);
            self::fail('A Web2App answer was accepted without its callback');
        } catch (SmartIdException $exception) {
            self::assertStringContainsString('needs the callback the app opened', $exception->getMessage());
        }

        $digest = DeviceLink::base64Url(hash('sha256', (string) base64_decode($session->sessionSecret, true), true));
        try {
            $authenticator->complete($session, $status, SmartIdCallback::fromUrl($callbackUrl . '&sessionSecretDigest=' . $digest . '&userChallengeVerifier=not-the-apps'));
            self::fail('A Web2App answer was accepted with a verifier the app never sent');
        } catch (SmartIdException $exception) {
            self::assertStringContainsString('verifier from the callback does not match', $exception->getMessage());
        }
    }

    private function requireMockScan(): void
    {
        if (!str_starts_with($this->configuration()->url, 'https://sid.demo.sk.ee/')) {
            self::markTestSkipped('SK\'s mock scan exists only beside the demo service, and ALLKIRI_SMARTID_URL points elsewhere');
        }
    }

    /**
     * Hand a link to SK's mock scan, as a person tapping or scanning it would.
     * A QR link has to go straight away: the service ignores one whose
     * elapsedSeconds has gone stale.
     *
     * @param array<string, string> $more
     */
    private function scan(string $link, string $flowType, array $more = []): void
    {
        $body = json_encode(['documentNumber' => self::MOCK_DOCUMENT, 'deviceLink' => $link, 'flowType' => $flowType] + $more, JSON_THROW_ON_ERROR);
        $response = self::http()->send(HttpRequest::post(self::MOCK_SCAN_URL, 'application/json', $body));

        self::assertSame(200, $response->status, 'the mock scan refused the link: ' . $response->body);
    }

    private static function qrLink(SmartIdSession $session, SmartIdConfiguration $configuration): string
    {
        self::assertNotNull($session->sessionSecret);

        return $session->deviceLink($configuration->scheme, $configuration->relyingPartyNameBase64())->url($session->sessionSecret, $session->elapsedSeconds());
    }

    /**
     * Our own validator first, then RIA's.
     */
    private static function assertAcceptedEverywhere(Allkiri $allkiri, string $bytes): void
    {
        $report = $allkiri->validator()->validate($bytes, 'smart-id.asice');
        self::assertSame(
            Indication::TotalPassed,
            $report->signatures[0]->indication,
            implode('; ', array_map(static fn($f): string => $f->code . ': ' . $f->message, $report->signatures[0]->errors())),
        );

        $siva = new SivaClient(self::http(60), (string) Environment::demo()->sivaUrl);
        $sivaReport = self::askSiva($siva, $bytes, 'smart-id.asice');

        self::assertSame('ASiC-E', $sivaReport->signatureForm);
        self::assertSame('XAdES_BASELINE_LT', $sivaReport->signatures[0]->signatureFormat);
        self::assertSame(
            'TOTAL-PASSED',
            $sivaReport->signatures[0]->indication,
            implode('; ', $sivaReport->signatures[0]->errors),
        );
    }

    private static function saveArtefact(string $name, string $bytes): void
    {
        $directory = getenv('ALLKIRI_ARTEFACTS');
        if (!\is_string($directory) || $directory === '' || !is_dir($directory)) {
            return;
        }
        file_put_contents(rtrim($directory, '/\\') . \DIRECTORY_SEPARATOR . $name, $bytes);
    }
}
