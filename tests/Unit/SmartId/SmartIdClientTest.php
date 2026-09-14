<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\SmartId;

use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Http\HttpResponse;
use Allkiri\Http\TransportException;
use Allkiri\SmartId\CertificateLevel;
use Allkiri\SmartId\DocumentNumber;
use Allkiri\SmartId\Interaction;
use Allkiri\SmartId\Interactions;
use Allkiri\SmartId\SemanticsIdentifier;
use Allkiri\SmartId\SmartIdApiException;
use Allkiri\SmartId\SmartIdClient;
use Allkiri\SmartId\SmartIdConfiguration;
use Allkiri\SmartId\SmartIdEndResult;
use Allkiri\SmartId\SmartIdSessionStatus;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Tests\Support\RecordingLogger;
use Allkiri\Tests\Support\SmartId\MockSmartIdService;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class SmartIdClientTest extends TestCase
{
    private MockHttpClient $http;

    private MockSmartIdService $service;

    private SmartIdClient $client;

    protected function setUp(): void
    {
        $this->http = new MockHttpClient();
        $this->service = MockSmartIdService::register($this->http);
        $this->client = new SmartIdClient($this->service->configuration(), $this->http);
    }

    private static function interactions(): Interactions
    {
        return Interactions::of(Interaction::displayTextAndPin('Sign in'));
    }

    // --- request shapes -----------------------------------------------------

    public function testEveryRequestNamesTheRelyingParty(): void
    {
        $this->client->certificateByDocumentNumber(new DocumentNumber(MockSmartIdService::DOCUMENT_NUMBER));

        $body = $this->service->received[0]['body'];
        self::assertSame(SmartIdConfiguration::DEMO_RELYING_PARTY_UUID, $body['relyingPartyUUID']);
        self::assertSame('TEST', $body['relyingPartyName']);
        self::assertSame('QUALIFIED', $body['certificateLevel']);
    }

    public function testTheCertificateLevelCanBeRaisedPerRequest(): void
    {
        $this->client->certificateByDocumentNumber(new DocumentNumber(MockSmartIdService::DOCUMENT_NUMBER), CertificateLevel::Qscd);

        self::assertSame('QSCD', $this->service->received[0]['body']['certificateLevel']);
    }

    public function testAPersonIsAddressedByTheirSemanticsIdentifier(): void
    {
        $this->client->startNotificationAuthentication(SemanticsIdentifier::estonian('40504040001'), random_bytes(64), self::interactions());

        self::assertStringEndsWith('/etsi/PNOEE-40504040001', $this->service->received[0]['path']);
    }

    public function testAnAccountIsAddressedByItsDocumentNumber(): void
    {
        $this->client->startNotificationAuthentication(new DocumentNumber(MockSmartIdService::DOCUMENT_NUMBER), random_bytes(64), self::interactions());

        self::assertStringEndsWith('/document/PNOEE-40504040001-MOCK-Q', $this->service->received[0]['path']);
    }

    public function testTheDeviceIpAddressIsOnlyAskedForWhenConfigured(): void
    {
        $this->client->startNotificationAuthentication(SemanticsIdentifier::estonian('40504040001'), random_bytes(64), self::interactions());
        self::assertArrayNotHasKey('requestProperties', $this->service->received[0]['body']);

        $sharing = new SmartIdClient($this->service->configuration()->withDeviceIpAddress(), $this->http);
        $sharing->startNotificationAuthentication(SemanticsIdentifier::estonian('40504040001'), random_bytes(64), self::interactions());

        self::assertSame(['shareMdClientIpAddress' => true], $this->service->received[1]['body']['requestProperties']);
    }

    public function testASignatureRequestCarriesTheDigestAndItsHashName(): void
    {
        $digest = hash('sha384', 'something', true);

        $this->client->startNotificationSignature(
            new DocumentNumber(MockSmartIdService::DOCUMENT_NUMBER),
            $digest,
            HashAlgorithm::SHA384,
            self::interactions(),
        );

        $parameters = $this->service->received[0]['body']['signatureProtocolParameters'];
        self::assertIsArray($parameters);
        self::assertSame(base64_encode($digest), $parameters['digest']);
        self::assertSame(['hashAlgorithm' => 'SHA-384'], $parameters['signatureAlgorithmParameters']);
    }

    public function testADeviceLinkSessionReturnsItsTokenAndSecret(): void
    {
        $response = $this->client->startAnonymousDeviceLinkAuthentication(random_bytes(64), self::interactions());

        self::assertNotSame('', $response->sessionId);
        self::assertNotSame('', $response->sessionToken);
        self::assertNotSame('', $response->sessionSecret);
        self::assertSame('https://smart-id.test/dl', $response->deviceLinkBase);
        self::assertStringEndsWith('/authentication/device-link/anonymous', $this->service->received[0]['path']);
    }

    public function testACallbackUrlIsSentWhenGiven(): void
    {
        $this->client->startAnonymousDeviceLinkAuthentication(random_bytes(64), self::interactions(), null, 'https://example.test/back');

        self::assertSame('https://example.test/back', $this->service->received[0]['body']['initialCallbackUrl']);
    }

    public function testANotificationSessionReturnsTheCodeToShow(): void
    {
        $started = $this->client->startNotificationSignature(
            new DocumentNumber(MockSmartIdService::DOCUMENT_NUMBER),
            hash('sha256', 'x', true),
            HashAlgorithm::SHA256,
            self::interactions(),
        );

        self::assertMatchesRegularExpression('/^\d{4}$/', $started['verificationCode']);
    }

    public function testThePollTimeoutIsPassedToTheService(): void
    {
        $client = new SmartIdClient($this->service->configuration()->withTimeouts(30_000, 120), $this->http);
        $this->service->runningPolls = 1;
        $sessionId = $this->client->startNotificationAuthentication(SemanticsIdentifier::estonian('40504040001'), random_bytes(64), self::interactions());

        $client->sessionStatus($sessionId);

        self::assertStringContainsString('timeoutMs=30000', (string) $this->http->lastRequest()?->url);
    }

    // --- session status -----------------------------------------------------

    public function testARunningSessionCarriesNothingElse(): void
    {
        $this->service->runningPolls = 1;
        $sessionId = $this->client->startNotificationAuthentication(SemanticsIdentifier::estonian('40504040001'), random_bytes(64), self::interactions());

        $status = $this->client->sessionStatus($sessionId);

        self::assertTrue($status->isRunning());
        self::assertNull($status->result);
        self::assertNull($status->signatureValue);
        self::assertNull($status->certificate);
    }

    public function testACompleteSessionIsFullyRead(): void
    {
        $sessionId = $this->client->startNotificationAuthentication(SemanticsIdentifier::estonian('40504040001'), random_bytes(64), self::interactions());

        $status = $this->client->sessionStatus($sessionId);

        self::assertTrue($status->isOk());
        self::assertSame(MockSmartIdService::DOCUMENT_NUMBER, $status->documentNumber?->value);
        self::assertSame('rsassa-pss', $status->signatureAlgorithmName);
        self::assertNotNull($status->pssParameters);
        self::assertTrue($status->pssParameters->isRfc6931Profile());
        self::assertNotNull($status->certificate);
        self::assertSame(CertificateLevel::Qualified, $status->certificateLevel);
        self::assertNotNull($status->serverRandom);
        self::assertSame('ACSP_V2', $status->signatureProtocol);
        self::assertFalse($status->isLegacyRsa());
    }

    public function testALegacyRsaAnswerIsRecognisedAsSuch(): void
    {
        $this->service->legacyRsa = true;
        $sessionId = $this->client->startNotificationAuthentication(SemanticsIdentifier::estonian('40504040001'), random_bytes(64), self::interactions());

        $status = $this->client->sessionStatus($sessionId);

        self::assertTrue($status->isLegacyRsa());
        self::assertNull($status->pssParameters);
        self::assertSame('sha256WithRSAEncryption', $status->signatureAlgorithmName);
    }

    /**
     * @return iterable<string, array{SmartIdEndResult}>
     */
    public static function endResults(): iterable
    {
        foreach (SmartIdEndResult::cases() as $result) {
            if ($result !== SmartIdEndResult::Ok) {
                yield $result->value => [$result];
            }
        }
    }

    #[DataProvider('endResults')]
    public function testEveryEndResultTheServiceCanSendIsRead(SmartIdEndResult $expected): void
    {
        $this->service->endResult = $expected;
        $sessionId = $this->client->startNotificationAuthentication(SemanticsIdentifier::estonian('40504040001'), random_bytes(64), self::interactions());

        $status = $this->client->sessionStatus($sessionId);

        self::assertTrue($status->isComplete());
        self::assertSame($expected, $status->result);
        self::assertNull($status->signatureValue);
    }

    // --- failures -----------------------------------------------------------

    /**
     * @return iterable<string, array{int, string, string}>
     */
    public static function httpFailures(): iterable
    {
        yield '400' => [400, SmartIdApiException::REASON_BAD_REQUEST, 'malformed'];
        yield '401' => [401, SmartIdApiException::REASON_UNAUTHORISED, 'not accepted'];
        yield '403' => [403, SmartIdApiException::REASON_UNAUTHORISED, 'ADVANCED'];
        yield '404' => [404, SmartIdApiException::REASON_ACCOUNT_NOT_FOUND, 'no Smart-ID account'];
        yield '429' => [429, SmartIdApiException::REASON_RATE_LIMITED, 'too many'];
        yield '471' => [471, SmartIdApiException::REASON_NO_SUITABLE_ACCOUNT, 'none of the requested kind'];
        yield '472' => [472, SmartIdApiException::REASON_SHOULD_VIEW_PORTAL, 'self-service portal'];
        yield '480' => [480, SmartIdApiException::REASON_CLIENT_TOO_OLD, 'no longer supported'];
        yield '500' => [500, SmartIdApiException::REASON_SERVER_ERROR, 'unexpectedly'];
        yield '580' => [580, SmartIdApiException::REASON_MAINTENANCE, 'maintenance'];
    }

    #[DataProvider('httpFailures')]
    public function testHttpStatusesBecomeTypedReasons(int $status, string $reason, string $expectedText): void
    {
        $http = new MockHttpClient();
        $http->respond(MockSmartIdService::URL, $status, 'application/json', '{"code":1,"message":"nope"}');
        $client = new SmartIdClient($this->service->configuration(), $http);

        try {
            $client->certificateByDocumentNumber(new DocumentNumber(MockSmartIdService::DOCUMENT_NUMBER));
            self::fail('Expected a SmartIdApiException');
        } catch (SmartIdApiException $exception) {
            self::assertSame($reason, $exception->reason);
            self::assertSame($status, $exception->status);
            self::assertStringContainsString($expectedText, $exception->getMessage());
            self::assertStringContainsString('nope', $exception->getMessage());
            // The request path names the account, and the message names the path.
            self::assertStringContainsString('/signature/certificate/PNOEE-[redacted]', $exception->getMessage());
            self::assertStringNotContainsString('40504040001', $exception->getMessage());
        }
    }

    public function testAnAccountWithNoUsableCertificateIsNotNamedInTheMessage(): void
    {
        $http = new MockHttpClient();
        $http->respond(MockSmartIdService::URL, 200, 'application/json', '{"state":"DOCUMENT_UNUSABLE"}');
        $client = new SmartIdClient($this->service->configuration(), $http);

        try {
            $client->certificateByDocumentNumber(new DocumentNumber(MockSmartIdService::DOCUMENT_NUMBER));
            self::fail('Expected a SmartIdApiException');
        } catch (SmartIdApiException $exception) {
            self::assertSame(SmartIdApiException::REASON_ACCOUNT_NOT_FOUND, $exception->reason);
            self::assertStringContainsString('PNOEE-[redacted] (state DOCUMENT_UNUSABLE)', $exception->getMessage());
            self::assertStringNotContainsString('40504040001', $exception->getMessage());
        }
    }

    public function testTheDebugLineNamesNoAccount(): void
    {
        $logger = new RecordingLogger();
        $client = new SmartIdClient($this->service->configuration(), $this->http, $logger);

        $client->certificateByDocumentNumber(new DocumentNumber(MockSmartIdService::DOCUMENT_NUMBER));

        $transcript = $logger->transcript();
        self::assertStringContainsString('Smart-ID POST ' . MockSmartIdService::URL . '/signature/certificate/PNOEE-[redacted]', $transcript);
        self::assertStringNotContainsString('40504040001', $transcript);
    }

    /**
     * The same status means different things depending on what was asked: a
     * missing account when starting, a forgotten session when polling.
     */
    public function testA404MeansSomethingElseWhenPolling(): void
    {
        $http = new MockHttpClient();
        $http->respond(MockSmartIdService::URL, 404, 'application/json', '{}');
        $client = new SmartIdClient($this->service->configuration(), $http);

        try {
            $client->sessionStatus('11111111-2222-3333-4444-555555555555');
            self::fail('Expected a SmartIdApiException');
        } catch (SmartIdApiException $exception) {
            self::assertSame(SmartIdApiException::REASON_SESSION_NOT_FOUND, $exception->reason);
        }
    }

    public function testATransportFailureIsNotMistakenForARefusal(): void
    {
        $http = new MockHttpClient();
        $http->on(MockSmartIdService::URL, static function (): HttpResponse {
            throw new TransportException('connection reset');
        });
        $client = new SmartIdClient($this->service->configuration(), $http);

        try {
            $client->certificateByDocumentNumber(new DocumentNumber(MockSmartIdService::DOCUMENT_NUMBER));
            self::fail('Expected a SmartIdApiException');
        } catch (SmartIdApiException $exception) {
            self::assertSame(SmartIdApiException::REASON_TRANSPORT, $exception->reason);
            self::assertNull($exception->status);
        }
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function malformedStatuses(): iterable
    {
        yield 'not json' => ['<html>maintenance</html>', 'not a JSON object'];
        yield 'no state' => ['{"result":{"endResult":"OK"}}', 'no state'];
        yield 'no result' => ['{"state":"COMPLETE"}', 'no result'];
        yield 'unknown end result' => ['{"state":"COMPLETE","result":{"endResult":"WHAT"}}', 'unknown end result'];
        yield 'unusable document number' => ['{"state":"COMPLETE","result":{"endResult":"OK","documentNumber":"nonsense"}}', 'unusable document number'];
        yield 'signature without an algorithm' => ['{"state":"COMPLETE","result":{"endResult":"OK","documentNumber":"PNOEE-1-MOCK-Q"},"signature":{"value":"AA=="}}', 'signature.signatureAlgorithm'];
        yield 'no account named' => ['{"state":"COMPLETE","result":{"endResult":"OK"}}', 'without naming the account'];
    }

    #[DataProvider('malformedStatuses')]
    public function testAnUnreadableStatusIsReportedAsSuch(string $body, string $expected): void
    {
        $http = new MockHttpClient();
        $http->respond(MockSmartIdService::URL, 200, 'application/json', $body);
        $client = new SmartIdClient($this->service->configuration(), $http);

        try {
            $client->sessionStatus('abc');
            self::fail('Expected a SmartIdApiException');
        } catch (SmartIdApiException $exception) {
            self::assertSame(SmartIdApiException::REASON_MALFORMED_RESPONSE, $exception->reason);
            self::assertStringContainsString($expected, $exception->getMessage());
        }
    }

    public function testAHashAlgorithmNoXadesMethodCoversIsRefused(): void
    {
        // The API accepts SHA-3, but no XML-DSig signature method in the
        // profile we produce describes it.
        $body = json_encode([
            'state' => SmartIdSessionStatus::STATE_COMPLETE,
            'result' => ['endResult' => 'OK', 'documentNumber' => MockSmartIdService::DOCUMENT_NUMBER],
            'signatureProtocol' => 'ACSP_V2',
            'interactionTypeUsed' => 'displayTextAndPIN',
            'signature' => [
                'value' => base64_encode('x'),
                'signatureAlgorithm' => 'rsassa-pss',
                'signatureAlgorithmParameters' => [
                    'hashAlgorithm' => 'SHA3-256',
                    'maskGenAlgorithm' => ['algorithm' => 'id-mgf1', 'parameters' => ['hashAlgorithm' => 'SHA3-256']],
                    'saltLength' => 32,
                    'trailerField' => '0xbc',
                ],
            ],
            'cert' => ['value' => $this->service->certificate()->base64(), 'certificateLevel' => 'QUALIFIED'],
        ], JSON_THROW_ON_ERROR);

        $http = new MockHttpClient();
        $http->respond(MockSmartIdService::URL, 200, 'application/json', $body);
        $client = new SmartIdClient($this->service->configuration(), $http);

        $this->expectExceptionMessageMatches('/SHA3-256.*cannot be used in a XAdES signature/');

        $client->sessionStatus('abc');
    }

    public function testAMaskGenerationFunctionOtherThanMgf1IsRefused(): void
    {
        $body = json_encode([
            'state' => SmartIdSessionStatus::STATE_COMPLETE,
            'result' => ['endResult' => 'OK', 'documentNumber' => MockSmartIdService::DOCUMENT_NUMBER],
            'signatureProtocol' => 'ACSP_V2',
            'interactionTypeUsed' => 'displayTextAndPIN',
            'signature' => [
                'value' => base64_encode('x'),
                'signatureAlgorithm' => 'rsassa-pss',
                'signatureAlgorithmParameters' => [
                    'hashAlgorithm' => 'SHA-256',
                    'maskGenAlgorithm' => ['algorithm' => 'id-mgf2', 'parameters' => ['hashAlgorithm' => 'SHA-256']],
                    'saltLength' => 32,
                    'trailerField' => '0xbc',
                ],
            ],
            'cert' => ['value' => $this->service->certificate()->base64(), 'certificateLevel' => 'QUALIFIED'],
        ], JSON_THROW_ON_ERROR);

        $http = new MockHttpClient();
        $http->respond(MockSmartIdService::URL, 200, 'application/json', $body);
        $client = new SmartIdClient($this->service->configuration(), $http);

        $this->expectExceptionMessageMatches('/only MGF1 is usable/');

        $client->sessionStatus('abc');
    }

    /**
     * A certificate-choice session signs nothing, and the service still sends a
     * `signature` object carrying only the flow type. That must read as no
     * signature rather than as a malformed one.
     */
    public function testACertificateChoiceSessionCarriesNoSignature(): void
    {
        $body = json_encode([
            'state' => SmartIdSessionStatus::STATE_COMPLETE,
            'result' => ['endResult' => 'OK', 'documentNumber' => MockSmartIdService::DOCUMENT_NUMBER],
            'signature' => ['flowType' => 'Notification'],
            'cert' => ['value' => $this->service->certificate()->base64(), 'certificateLevel' => 'QUALIFIED'],
        ], JSON_THROW_ON_ERROR);

        $http = new MockHttpClient();
        $http->respond(MockSmartIdService::URL, 200, 'application/json', $body);
        $client = new SmartIdClient($this->service->configuration(), $http);

        $status = $client->sessionStatus('abc');

        self::assertTrue($status->isOk());
        self::assertNull($status->signatureValue);
        self::assertNull($status->pssParameters);
        self::assertNull($status->signatureAlgorithmName);
        self::assertNull($status->interactionTypeUsed);
        self::assertNotNull($status->certificate);
        self::assertSame(MockSmartIdService::DOCUMENT_NUMBER, $status->documentNumber?->value);
    }

    public function testACertificateChoiceSessionCanBeStarted(): void
    {
        $sessionId = $this->client->startNotificationCertificateChoice(SemanticsIdentifier::estonian('40504040001'), CertificateLevel::Qscd);

        self::assertNotSame('', $sessionId);
        self::assertStringContainsString('/signature/certificate-choice/notification/etsi/', $this->service->received[0]['path']);
        self::assertSame('QSCD', $this->service->received[0]['body']['certificateLevel']);
    }
}
