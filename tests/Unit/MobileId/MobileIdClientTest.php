<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\MobileId;

use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Http\HttpResponse;
use Allkiri\Http\TransportException;
use Allkiri\MobileId\CertificateNotFoundException;
use Allkiri\MobileId\DisplayTextFormat;
use Allkiri\MobileId\MobileIdApiException;
use Allkiri\MobileId\MobileIdClient;
use Allkiri\MobileId\MobileIdConfiguration;
use Allkiri\MobileId\MobileIdIdentity;
use Allkiri\MobileId\MobileIdLanguage;
use Allkiri\MobileId\MobileIdResult;
use Allkiri\MobileId\MobileIdSession;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Tests\Support\MobileId\MockMobileIdService;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Tests\Support\RecordingLogger;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class MobileIdClientTest extends TestCase
{
    private const IDENTITY_CODE = '38001085718';

    private static function identity(): MobileIdIdentity
    {
        return new MobileIdIdentity('+37200000766', self::IDENTITY_CODE);
    }

    /**
     * @return array{MobileIdClient, MockMobileIdService, MockHttpClient}
     */
    private static function client(?MobileIdConfiguration $configuration = null): array
    {
        $http = new MockHttpClient();
        $service = MockMobileIdService::register($http);

        return [new MobileIdClient($configuration ?? $service->configuration(), $http), $service, $http];
    }

    // --- certificate --------------------------------------------------------

    public function testFetchesTheSigningCertificate(): void
    {
        [$client, $service] = self::client();

        $certificate = $client->certificate(self::identity());

        self::assertTrue($certificate->equals($service->certificate()));
        self::assertSame([
            'relyingPartyUUID' => MobileIdConfiguration::DEMO_RELYING_PARTY_UUID,
            'relyingPartyName' => 'TEST',
            'phoneNumber' => '+37200000766',
            'nationalIdentityNumber' => self::IDENTITY_CODE,
        ], $service->received[0]);
    }

    /**
     * Whether someone has Mobile-ID is personal data, so neither the log nor
     * the message names them. The application still has the identity, on the
     * exception.
     */
    public function testSaysSoWhenThePersonHasNoMobileIdWithoutNamingThem(): void
    {
        $http = new MockHttpClient();
        $service = MockMobileIdService::register($http);
        $service->certificateFound = false;
        $logger = new RecordingLogger();
        $client = new MobileIdClient($service->configuration(), $http, $logger);

        try {
            $client->certificate(self::identity());
            self::fail('Expected a CertificateNotFoundException');
        } catch (CertificateNotFoundException $exception) {
            self::assertEquals(self::identity(), $exception->identity);
            self::assertSame('NOT_FOUND', $exception->result);
            self::assertStringContainsString('NOT_FOUND', $exception->getMessage());
            self::assertStringNotContainsString(self::IDENTITY_CODE, $exception->getMessage());
            self::assertStringNotContainsString('37200000766', $exception->getMessage());
        }

        $transcript = $logger->transcript();
        self::assertStringContainsString('Mobile-ID has no certificate: NOT_FOUND', $transcript);
        self::assertStringNotContainsString(self::IDENTITY_CODE, $transcript);
        self::assertStringNotContainsString('37200000766', $transcript);
    }

    // --- starting a session -------------------------------------------------

    public function testStartsAnAuthenticationWithEverythingTheServiceNeeds(): void
    {
        $configuration = (new MobileIdConfiguration(MockMobileIdService::URL, MobileIdConfiguration::DEMO_RELYING_PARTY_UUID, 'TEST'))
            ->withLanguage(MobileIdLanguage::English)
            ->withDisplayText('Log in to allkiri');
        [$client, $service] = self::client($configuration);

        $sessionId = $client->startAuthentication(self::identity(), str_repeat("\x01", 32), HashAlgorithm::SHA256);

        self::assertNotSame('', $sessionId);
        $request = $service->received[0];
        self::assertSame(base64_encode(str_repeat("\x01", 32)), $request['hash']);
        self::assertSame('SHA256', $request['hashType']);
        self::assertSame('ENG', $request['language']);
        self::assertSame('Log in to allkiri', $request['displayText']);
        self::assertSame('GSM-7', $request['displayTextFormat']);
    }

    public function testOmitsTheDisplayTextWhenThereIsNone(): void
    {
        [$client, $service] = self::client();

        $client->startSignature(self::identity(), str_repeat("\x02", 48), HashAlgorithm::SHA384);

        self::assertArrayNotHasKey('displayText', $service->received[0]);
        self::assertArrayNotHasKey('displayTextFormat', $service->received[0]);
        self::assertSame('SHA384', $service->received[0]['hashType']);
    }

    public function testDisplayTextSurvivesAsUtf8(): void
    {
        $configuration = (new MobileIdConfiguration(MockMobileIdService::URL, MobileIdConfiguration::DEMO_RELYING_PARTY_UUID, 'TEST'))
            ->withDisplayText('Nõustun tingimustega', DisplayTextFormat::Ucs2);
        [$client, $service] = self::client($configuration);

        $client->startSignature(self::identity(), str_repeat("\x03", 32), HashAlgorithm::SHA256);

        self::assertSame('Nõustun tingimustega', $service->received[0]['displayText']);
        self::assertSame('UCS-2', $service->received[0]['displayTextFormat']);
    }

    // --- session status -----------------------------------------------------

    public function testReportsAStillRunningSession(): void
    {
        [$client, $service] = self::client();
        $service->runningPolls = 1;
        $sessionId = $client->startSignature(self::identity(), hash('sha256', 'x', true), HashAlgorithm::SHA256);

        $status = $client->status(MobileIdSession::TYPE_SIGNATURE, $sessionId);

        self::assertTrue($status->isRunning());
        self::assertNull($status->result);
        self::assertNull($status->signatureValue);
    }

    public function testReturnsTheSignatureAndAlgorithmWhenDone(): void
    {
        [$client, $service] = self::client();
        $service->expectToSign('what the phone signs');
        $sessionId = $client->startSignature(self::identity(), hash('sha256', 'what the phone signs', true), HashAlgorithm::SHA256);

        $status = $client->status(MobileIdSession::TYPE_SIGNATURE, $sessionId);

        self::assertTrue($status->isComplete());
        self::assertTrue($status->isOk());
        self::assertSame(SignatureAlgorithm::ES256, $status->signatureAlgorithm);
        self::assertNotSame('', $status->requireSignature());
        // Signing sessions carry no certificate; it was fetched beforehand.
        self::assertNull($status->certificate);
    }

    public function testAnAuthenticationSessionAlsoReturnsTheCertificate(): void
    {
        [$client, $service] = self::client();
        $service->expectToSign('challenge');
        $sessionId = $client->startAuthentication(self::identity(), hash('sha256', 'challenge', true), HashAlgorithm::SHA256);

        $status = $client->status(MobileIdSession::TYPE_AUTHENTICATION, $sessionId);

        self::assertNotNull($status->certificate);
        self::assertTrue($status->certificate->equals($service->certificate()));
    }

    public function testPassesThePollTimeoutToTheService(): void
    {
        $configuration = (new MobileIdConfiguration(MockMobileIdService::URL, MobileIdConfiguration::DEMO_RELYING_PARTY_UUID, 'TEST'))
            ->withTimeouts(30_000, 120);
        [$client, $service, $http] = self::client($configuration);
        $service->runningPolls = 1;
        $sessionId = $client->startSignature(self::identity(), hash('sha256', 'x', true), HashAlgorithm::SHA256);

        $client->status(MobileIdSession::TYPE_SIGNATURE, $sessionId);

        self::assertStringContainsString('timeoutMs=30000', (string) $http->lastRequest()?->url);
    }

    /**
     * @return iterable<string, array{MobileIdResult}>
     */
    public static function failureResults(): iterable
    {
        foreach (MobileIdResult::cases() as $result) {
            if ($result !== MobileIdResult::Ok) {
                yield $result->value => [$result];
            }
        }
    }

    #[DataProvider('failureResults')]
    public function testEveryPublishedFailureIsReportedAsItself(MobileIdResult $expected): void
    {
        [$client, $service] = self::client();
        $service->result = $expected;
        $sessionId = $client->startSignature(self::identity(), hash('sha256', 'x', true), HashAlgorithm::SHA256);

        $status = $client->status(MobileIdSession::TYPE_SIGNATURE, $sessionId);

        self::assertTrue($status->isComplete());
        self::assertSame($expected, $status->result);
        self::assertNull($status->signatureValue);
    }

    // --- failures -----------------------------------------------------------

    /**
     * @return iterable<string, array{int, string}>
     */
    public static function httpFailures(): iterable
    {
        yield '400' => [400, MobileIdApiException::REASON_BAD_REQUEST];
        yield '401' => [401, MobileIdApiException::REASON_UNAUTHORISED];
        yield '403' => [403, MobileIdApiException::REASON_UNAUTHORISED];
        yield '404' => [404, MobileIdApiException::REASON_SESSION_NOT_FOUND];
        yield '405' => [405, MobileIdApiException::REASON_BAD_REQUEST];
        yield '429' => [429, MobileIdApiException::REASON_RATE_LIMITED];
        yield '471' => [471, MobileIdApiException::REASON_UNAUTHORISED];
        yield '472' => [472, MobileIdApiException::REASON_UNAUTHORISED];
        yield '480' => [480, MobileIdApiException::REASON_BAD_REQUEST];
        yield '500' => [500, MobileIdApiException::REASON_SERVER_ERROR];
        yield '580' => [580, MobileIdApiException::REASON_SERVER_ERROR];
    }

    #[DataProvider('httpFailures')]
    public function testHttpStatusesBecomeTypedReasons(int $status, string $reason): void
    {
        $http = new MockHttpClient();
        $http->respond(MockMobileIdService::URL, $status, 'application/json', '{"error":"nope"}');
        $client = new MobileIdClient(new MobileIdConfiguration(MockMobileIdService::URL, MobileIdConfiguration::DEMO_RELYING_PARTY_UUID, 'TEST'), $http);

        try {
            $client->certificate(self::identity());
            self::fail('Expected a MobileIdApiException');
        } catch (MobileIdApiException $exception) {
            self::assertSame($reason, $exception->reason);
            self::assertSame($status, $exception->status);
            self::assertStringContainsString('nope', $exception->getMessage());
        }
    }

    public function testATransportFailureIsNotMistakenForARefusal(): void
    {
        $http = new MockHttpClient();
        $http->on(MockMobileIdService::URL, static function (): HttpResponse {
            throw new TransportException('connection reset');
        });
        $client = new MobileIdClient(new MobileIdConfiguration(MockMobileIdService::URL, MobileIdConfiguration::DEMO_RELYING_PARTY_UUID, 'TEST'), $http);

        try {
            $client->certificate(self::identity());
            self::fail('Expected a MobileIdApiException');
        } catch (MobileIdApiException $exception) {
            self::assertSame(MobileIdApiException::REASON_TRANSPORT, $exception->reason);
            self::assertNull($exception->status);
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedResponses(): iterable
    {
        yield 'not json' => ['<html>maintenance</html>'];
        yield 'no state' => ['{"result":"OK"}'];
        yield 'unknown result' => ['{"state":"COMPLETE","result":"WHAT"}'];
        yield 'no signature' => ['{"state":"COMPLETE","result":"OK"}'];
        yield 'signature not base64' => ['{"state":"COMPLETE","result":"OK","signature":{"value":"!!!","algorithm":"SHA256WithECEncryption"}}'];
    }

    #[DataProvider('malformedResponses')]
    public function testAnUnreadableAnswerIsReportedAsSuch(string $body): void
    {
        $http = new MockHttpClient();
        $http->respond(MockMobileIdService::URL, 200, 'application/json', $body);
        $client = new MobileIdClient(new MobileIdConfiguration(MockMobileIdService::URL, MobileIdConfiguration::DEMO_RELYING_PARTY_UUID, 'TEST'), $http);

        $this->expectException(MobileIdApiException::class);

        $client->status(MobileIdSession::TYPE_SIGNATURE, 'abc');
    }

    public function testAnUnreadableCertificateIsReportedAsSuch(): void
    {
        $http = new MockHttpClient();
        $http->respond(MockMobileIdService::URL, 200, 'application/json', '{"result":"OK","cert":"bm90IGEgY2VydGlmaWNhdGU="}');
        $client = new MobileIdClient(new MobileIdConfiguration(MockMobileIdService::URL, MobileIdConfiguration::DEMO_RELYING_PARTY_UUID, 'TEST'), $http);

        $this->expectException(MobileIdApiException::class);

        $client->certificate(self::identity());
    }

    // --- algorithm names ----------------------------------------------------

    /**
     * @return iterable<string, array{string, SignatureAlgorithm|null}>
     */
    public static function algorithmNames(): iterable
    {
        yield 'ec 256' => ['SHA256WithECEncryption', SignatureAlgorithm::ES256];
        yield 'ec 384' => ['SHA384WithECEncryption', SignatureAlgorithm::ES384];
        yield 'ec 512' => ['SHA512WithECEncryption', SignatureAlgorithm::ES512];
        yield 'rsa 256' => ['SHA256WithRSAEncryption', SignatureAlgorithm::RS256];
        yield 'rsa 512' => ['SHA512WithRSAEncryption', SignatureAlgorithm::RS512];
        yield 'unknown' => ['SHA1WithRSAEncryption', null];
        yield 'nonsense' => ['whatever', null];
    }

    #[DataProvider('algorithmNames')]
    public function testAlgorithmNamesAreRecognised(string $name, ?SignatureAlgorithm $expected): void
    {
        self::assertSame($expected, MobileIdClient::signatureAlgorithm($name));
    }

    public function testAnRsaSignerIsHandledToo(): void
    {
        $http = new MockHttpClient();
        $service = MockMobileIdService::register($http, TestPki::signerRsa());
        $client = new MobileIdClient($service->configuration(), $http);
        $service->expectToSign('rsa please');

        $sessionId = $client->startSignature(self::identity(), hash('sha256', 'rsa please', true), HashAlgorithm::SHA256);
        $status = $client->status(MobileIdSession::TYPE_SIGNATURE, $sessionId);

        self::assertSame(SignatureAlgorithm::RS256, $status->signatureAlgorithm);
    }
}
