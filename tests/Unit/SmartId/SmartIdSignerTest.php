<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\SmartId;

use Allkiri\Container\AsicContainer;
use Allkiri\Container\AsicWriter;
use Allkiri\Container\DataFile;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Signing\SessionMismatchException;
use Allkiri\Signing\SignatureLevel;
use Allkiri\Signing\SigningOptions;
use Allkiri\SmartId\CertificateLevel;
use Allkiri\SmartId\DocumentNumber;
use Allkiri\SmartId\FlowType;
use Allkiri\SmartId\Interaction;
use Allkiri\SmartId\Interactions;
use Allkiri\SmartId\SmartIdApiException;
use Allkiri\SmartId\SmartIdClient;
use Allkiri\SmartId\SmartIdEndResult;
use Allkiri\SmartId\SmartIdException;
use Allkiri\SmartId\SmartIdPoller;
use Allkiri\SmartId\SmartIdSessionException;
use Allkiri\SmartId\SmartIdSigner;
use Allkiri\SmartId\SmartIdSigningSession;
use Allkiri\SmartId\VerificationCode;
use Allkiri\Tests\Support\MobileId\NullSleeper;
use Allkiri\Tests\Support\SigningFixture;
use Allkiri\Tests\Support\SmartId\MockSmartIdService;
use Allkiri\Validation\ContainerValidator;
use Allkiri\Validation\Report\Indication;
use Allkiri\Validation\SignatureValidator;
use Allkiri\Validation\ValidationPolicy;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The whole Smart-ID signing flow, offline: a mock service holding an RSA test
 * key, the mock timestamp authority and OCSP responder from the signing
 * fixture, and the library's own validator passing judgment on the result.
 *
 * Smart-ID keys are RSA and SK deprecates PKCS#1 v1.5, so these containers are
 * the library's only RSASSA-PSS signatures made end to end.
 */
#[CoversNothing]
final class SmartIdSignerTest extends TestCase
{
    private SigningFixture $fixture;

    private MockSmartIdService $service;

    private SmartIdClient $client;

    private SmartIdSigner $signer;

    protected function setUp(): void
    {
        $this->rebuild();
    }

    private function rebuild(?HashAlgorithm $hash = null): void
    {
        $this->fixture = new SigningFixture();
        $this->service = MockSmartIdService::register($this->fixture->http);
        $configuration = $this->service->configuration();
        if ($hash !== null) {
            $configuration = $configuration->withSigningHashAlgorithm($hash);
        }
        $this->client = new SmartIdClient($configuration, $this->fixture->http);
        $this->signer = new SmartIdSigner($this->client, $this->fixture->signingService);
    }

    private static function container(): AsicContainer
    {
        return AsicContainer::create(DataFile::fromString('leping.txt', "Tere, allkiri!\n"));
    }

    private static function documentNumber(): DocumentNumber
    {
        return new DocumentNumber(MockSmartIdService::DOCUMENT_NUMBER);
    }

    private static function interactions(): Interactions
    {
        return Interactions::of(Interaction::confirmationMessage('Please sign the lease'));
    }

    // --- certificates -------------------------------------------------------

    public function testTheCertificateIsFetchedWithoutAskingThePersonAnything(): void
    {
        $certificate = $this->signer->certificate(self::documentNumber());

        self::assertTrue($certificate->certificate->equals($this->service->certificate()));
        self::assertSame(CertificateLevel::Qualified, $certificate->level);
        self::assertSame(MockSmartIdService::DOCUMENT_NUMBER, $certificate->documentNumber->value);
        // One request, and no session was started.
        self::assertCount(1, $this->service->received);
    }

    public function testAnAccountWithNoCertificateIsReported(): void
    {
        $this->service->certificateFound = false;

        try {
            $this->signer->certificate(self::documentNumber());
            self::fail('Expected a SmartIdApiException');
        } catch (SmartIdApiException $exception) {
            self::assertSame(SmartIdApiException::REASON_ACCOUNT_NOT_FOUND, $exception->reason);
        }
    }

    // --- signing ------------------------------------------------------------

    public function testStartingPreparesTheSignatureAndSendsItsDigest(): void
    {
        $signing = $this->signer->startNotification(self::container(), self::documentNumber(), self::interactions());

        self::assertSame(SignatureAlgorithm::PS256, $signing->dataToBeSigned->algorithm, 'PSS is the default, not PKCS#1');
        self::assertMatchesRegularExpression('/^\d{4}$/', (string) $signing->verificationCode());

        $body = $this->service->lastRequestTo('/signature/notification');
        $parameters = $body['signatureProtocolParameters'];
        self::assertIsArray($parameters);
        self::assertSame(base64_encode($signing->dataToBeSigned->digest), $parameters['digest']);
        self::assertSame('rsassa-pss', $parameters['signatureAlgorithm']);
        self::assertSame(['hashAlgorithm' => 'SHA-256'], $parameters['signatureAlgorithmParameters']);
        self::assertSame('RAW_DIGEST_SIGNATURE', $body['signatureProtocol']);
    }

    /**
     * @return iterable<string, array{HashAlgorithm, SignatureAlgorithm, string}>
     */
    public static function hashAlgorithms(): iterable
    {
        yield 'SHA-256' => [HashAlgorithm::SHA256, SignatureAlgorithm::PS256, 'sha256-rsa-MGF1'];
        yield 'SHA-384' => [HashAlgorithm::SHA384, SignatureAlgorithm::PS384, 'sha384-rsa-MGF1'];
        yield 'SHA-512' => [HashAlgorithm::SHA512, SignatureAlgorithm::PS512, 'sha512-rsa-MGF1'];
    }

    #[DataProvider('hashAlgorithms')]
    public function testAFullLtSignatureIsProducedAndValidates(HashAlgorithm $hash, SignatureAlgorithm $expected, string $expectedUri): void
    {
        $this->rebuild($hash);
        $container = self::container();

        $signing = $this->signer->startNotification($container, self::documentNumber(), self::interactions());
        self::assertSame($expected, $signing->dataToBeSigned->algorithm);

        $this->service->expectToSign($signing->dataToBeSigned->signedInfoCanonical);
        $result = $this->signer->poll($container, $signing);

        self::assertNotNull($result);
        self::assertSame(SignatureLevel::LT, $result->level);
        self::assertNotNull($result->timestampTime);
        self::assertNotNull($result->ocspProducedAt);

        self::assertSame(Indication::TotalPassed, $this->validate((new AsicWriter())->write($result->container)));

        // The signature must declare the RFC 6931 PSS method, not a plain one.
        $signatureFile = $result->container->signatureFile($result->signatureFileName);
        self::assertNotNull($signatureFile);
        $xml = $signatureFile->xml;
        self::assertStringContainsString($expectedUri, $xml);
    }

    public function testPollingReturnsNullWhileThePersonIsStillDeciding(): void
    {
        $this->service->runningPolls = 1;
        $container = self::container();
        $signing = $this->signer->startNotification($container, self::documentNumber(), self::interactions());
        $this->service->expectToSign($signing->dataToBeSigned->signedInfoCanonical);

        self::assertNull($this->signer->poll($container, $signing));
        self::assertNotNull($this->signer->poll($container, $signing));
    }

    public function testBlockingSigningWaitsForThePerson(): void
    {
        $this->service->runningPolls = 3;
        $container = self::container();
        $signing = $this->signer->startNotification($container, self::documentNumber(), self::interactions());
        $this->service->expectToSign($signing->dataToBeSigned->signedInfoCanonical);

        $result = $this->signer->sign($container, $signing, new SmartIdPoller($this->client, new NullSleeper()));

        self::assertSame(SignatureLevel::LT, $result->level);
    }

    public function testADeviceLinkSigningSessionYieldsALinkForTheApp(): void
    {
        $this->service->flowType = FlowType::Qr;
        $container = self::container();

        $signing = $this->signer->startDeviceLink($container, self::documentNumber(), self::interactions());

        self::assertTrue($signing->session->isDeviceLink());
        self::assertSame(VerificationCode::forData($signing->dataToBeSigned->digest), $signing->verificationCode());

        $configuration = $this->service->configuration();
        self::assertNotNull($signing->session->sessionSecret);
        $url = $signing->session
            ->deviceLink($configuration->scheme, $configuration->relyingPartyNameBase64())
            ->url($signing->session->sessionSecret, 0);

        self::assertStringContainsString('sessionType=sign', $url);
        self::assertStringContainsString('authCode=', $url);

        $this->service->expectToSign($signing->dataToBeSigned->signedInfoCanonical);
        $result = $this->signer->poll($container, $signing);

        self::assertNotNull($result);
        self::assertSame(Indication::TotalPassed, $this->validate((new AsicWriter())->write($result->container)));
    }

    public function testTheSigningSessionSurvivesJsonBetweenTwoRequests(): void
    {
        $container = self::container();
        $signing = $this->signer->startNotification($container, self::documentNumber(), self::interactions());
        $this->service->expectToSign($signing->dataToBeSigned->signedInfoCanonical);

        $restored = SmartIdSigningSession::fromJson(json_encode($signing, JSON_THROW_ON_ERROR));
        $result = $this->signer->poll($container, $restored);

        self::assertNotNull($result);
        self::assertSame(Indication::TotalPassed, $this->validate((new AsicWriter())->write($result->container)));
    }

    public function testASignatureCanBeAppendedToAnAlreadySignedContainer(): void
    {
        $container = self::container();

        $first = $this->signer->startNotification($container, self::documentNumber(), self::interactions());
        $this->service->expectToSign($first->dataToBeSigned->signedInfoCanonical);
        $once = $this->signer->poll($container, $first);
        self::assertNotNull($once);

        $second = $this->signer->startNotification($once->container, self::documentNumber(), self::interactions());
        $this->service->expectToSign($second->dataToBeSigned->signedInfoCanonical);
        $twice = $this->signer->poll($once->container, $second);

        self::assertNotNull($twice);
        self::assertSame('META-INF/signatures0.xml', $once->signatureFileName);
        self::assertSame('META-INF/signatures1.xml', $twice->signatureFileName);
        self::assertSame(Indication::TotalPassed, $this->validate((new AsicWriter())->write($twice->container)));
    }

    // --- refusals -----------------------------------------------------------

    public function testARefusedSignatureIsReportedAsRefused(): void
    {
        $this->service->endResult = SmartIdEndResult::UserRefused;
        $container = self::container();
        $signing = $this->signer->startNotification($container, self::documentNumber(), self::interactions());

        try {
            $this->signer->poll($container, $signing);
            self::fail('Expected a SmartIdSessionException');
        } catch (SmartIdSessionException $exception) {
            self::assertSame(SmartIdEndResult::UserRefused, $exception->result);
        }
    }

    public function testATamperedContainerCannotBeFinalized(): void
    {
        $container = self::container();
        $signing = $this->signer->startNotification($container, self::documentNumber(), self::interactions());
        $this->service->expectToSign($signing->dataToBeSigned->signedInfoCanonical);

        $tampered = AsicContainer::create(DataFile::fromString('leping.txt', "Tere, vale leping!\n"));

        $this->expectException(SessionMismatchException::class);

        $this->signer->poll($tampered, $signing);
    }

    public function testACorruptSignatureIsRefusedBeforeAnyTimestampIsBought(): void
    {
        $this->service->corruptSignature = true;
        $container = self::container();
        $signing = $this->signer->startNotification($container, self::documentNumber(), self::interactions());
        $this->service->expectToSign($signing->dataToBeSigned->signedInfoCanonical);

        $timestampsBefore = $this->fixture->tsa->requests;

        try {
            $this->signer->poll($container, $signing);
            self::fail('Expected the signature to be refused');
        } catch (\Throwable) {
            self::assertSame($timestampsBefore, $this->fixture->tsa->requests, 'no timestamp should be bought for a bad signature');
        }
    }

    /**
     * The XAdES already declares the method it was prepared with, so a service
     * that signs with a different one would make the container describe itself
     * wrongly. That must fail rather than be written out.
     */
    public function testAnAnswerInAnotherAlgorithmIsRefused(): void
    {
        $container = self::container();
        $signing = $this->signer->startNotification($container, self::documentNumber(), self::interactions());
        $this->service->expectToSign($signing->dataToBeSigned->signedInfoCanonical);
        $this->service->legacyRsa = true;

        $this->expectExceptionMessageMatches('/prepared as PS256/');

        $this->signer->poll($container, $signing);
    }

    public function testPssParametersNoXmlDsigMethodDescribesAreRefused(): void
    {
        $container = self::container();
        $signing = $this->signer->startNotification($container, self::documentNumber(), self::interactions());
        $this->service->expectToSign($signing->dataToBeSigned->signedInfoCanonical);
        $this->service->saltLengthOverride = 20;

        $this->expectExceptionMessageMatches('/no XML-DSig method describes/');

        $this->signer->poll($container, $signing);
    }

    /**
     * Asking for PKCS#1 deliberately still has to work, because some accounts
     * may only offer it, and the container must then declare RS256.
     */
    public function testAnExplicitPkcs1RequestProducesAPkcs1Container(): void
    {
        $container = self::container();
        $this->service->legacyRsa = true;

        $signing = $this->signer->startNotification(
            $container,
            self::documentNumber(),
            self::interactions(),
            (new SigningOptions())->withAlgorithm(SignatureAlgorithm::RS256),
        );
        $this->service->expectToSign($signing->dataToBeSigned->signedInfoCanonical);

        $result = $this->signer->poll($container, $signing);

        self::assertNotNull($result);
        self::assertSame(Indication::TotalPassed, $this->validate((new AsicWriter())->write($result->container)));

        $signatureFile = $result->container->signatureFile($result->signatureFileName);
        self::assertNotNull($signatureFile);
        $xml = $signatureFile->xml;
        self::assertStringContainsString('rsa-sha256', $xml);
        self::assertStringNotContainsString('MGF1', $xml);
    }

    public function testAnAuthenticationAnswerCannotFinishASigningSession(): void
    {
        $container = self::container();
        $signing = $this->signer->startNotification($container, self::documentNumber(), self::interactions());
        $this->service->expectToSign($signing->dataToBeSigned->signedInfoCanonical);

        // An authentication session's status, which names the other protocol.
        $authenticationSessionId = $this->client->startNotificationAuthentication(
            self::documentNumber(),
            random_bytes(64),
            self::interactions(),
        );
        $status = $this->client->sessionStatus($authenticationSessionId);

        $this->expectException(SmartIdException::class);

        $this->signer->complete($container, $signing, $status);
    }

    private function validate(string $bytes): Indication
    {
        $policy = new ValidationPolicy();
        $validator = new ContainerValidator(
            new SignatureValidator($this->fixture->trustStore, $policy),
            $this->fixture->clock,
            $policy,
        );

        $report = $validator->validate($bytes, 'leping.asice');
        $signature = $report->signatures[\count($report->signatures) - 1];

        self::assertSame([], $report->containerFindings, 'the container itself must be well formed');
        self::assertSame(
            [],
            $signature->errors(),
            implode('; ', array_map(static fn($f): string => $f->code . ': ' . $f->message, $signature->errors())),
        );

        return $signature->indication;
    }
}
