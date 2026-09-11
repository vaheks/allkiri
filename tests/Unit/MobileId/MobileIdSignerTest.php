<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\MobileId;

use Allkiri\Container\AsicContainer;
use Allkiri\Container\AsicWriter;
use Allkiri\Container\DataFile;
use Allkiri\Crypto\KeyPair;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\MobileId\CertificateNotFoundException;
use Allkiri\MobileId\MobileIdClient;
use Allkiri\MobileId\MobileIdIdentity;
use Allkiri\MobileId\MobileIdPoller;
use Allkiri\MobileId\MobileIdResult;
use Allkiri\MobileId\MobileIdSession;
use Allkiri\MobileId\MobileIdSessionException;
use Allkiri\MobileId\MobileIdSigner;
use Allkiri\MobileId\MobileIdSigningSession;
use Allkiri\MobileId\VerificationCode;
use Allkiri\Signing\SessionMismatchException;
use Allkiri\Signing\SignatureLevel;
use Allkiri\Signing\SigningOptions;
use Allkiri\Tests\Support\MobileId\MockMobileIdService;
use Allkiri\Tests\Support\MobileId\NullSleeper;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Tests\Support\SigningFixture;
use Allkiri\Validation\ContainerValidator;
use Allkiri\Validation\Report\Indication;
use Allkiri\Validation\SignatureValidator;
use Allkiri\Validation\ValidationPolicy;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The whole Mobile-ID signing flow, offline: a mock service holding the
 * signer's key, the mock TSA and OCSP responder from the signing fixture, and
 * the library's own validator passing judgment on the result.
 */
#[CoversNothing]
final class MobileIdSignerTest extends TestCase
{
    private SigningFixture $fixture;

    private MockMobileIdService $service;

    private MobileIdClient $client;

    private MobileIdSigner $signer;

    protected function setUp(): void
    {
        $this->fixture = new SigningFixture();
        $this->service = MockMobileIdService::register($this->fixture->http);
        $this->client = new MobileIdClient($this->service->configuration(), $this->fixture->http);
        $this->signer = new MobileIdSigner($this->client, $this->fixture->signingService);
    }

    /**
     * Start over with a different key. The whole fixture is rebuilt because a
     * mock route cannot be replaced, only added to.
     */
    private function useSigner(KeyPair $keyPair): void
    {
        $this->fixture = new SigningFixture();
        $this->service = MockMobileIdService::register($this->fixture->http, $keyPair);
        $this->client = new MobileIdClient($this->service->configuration(), $this->fixture->http);
        $this->signer = new MobileIdSigner($this->client, $this->fixture->signingService);
    }

    private static function container(): AsicContainer
    {
        return AsicContainer::create(DataFile::fromString('leping.txt', "Tere, allkiri!\n"));
    }

    private static function identity(): MobileIdIdentity
    {
        return new MobileIdIdentity('+37200000766', '38001085718');
    }

    // --- starting -----------------------------------------------------------

    public function testStartingFetchesTheCertificateAndAsksForTheDigest(): void
    {
        $signing = $this->signer->start(self::container(), self::identity());

        self::assertSame(MobileIdSession::TYPE_SIGNATURE, $signing->session->type);
        self::assertTrue($signing->dataToBeSigned->signerCertificate->equals($this->service->certificate()));

        // The certificate request first, then the signing request carrying the
        // digest of what was prepared.
        self::assertCount(2, $this->service->received);
        self::assertSame($signing->dataToBeSigned->digestBase64(), $this->service->received[1]['hash']);
        self::assertSame($signing->dataToBeSigned->hashName(), $this->service->received[1]['hashType']);
    }

    public function testTheVerificationCodeComesFromTheDigestThatWasSent(): void
    {
        $signing = $this->signer->start(self::container(), self::identity());

        self::assertSame(VerificationCode::forHash($signing->dataToBeSigned->digest), $signing->verificationCode());
        self::assertMatchesRegularExpression('/^\d{4}$/', $signing->verificationCode());
    }

    public function testSigningStopsBeforeAnythingIsPreparedWhenThereIsNoMobileId(): void
    {
        $this->service->certificateFound = false;

        $this->expectException(CertificateNotFoundException::class);

        $this->signer->start(self::container(), self::identity());
    }

    // --- completing ---------------------------------------------------------

    /**
     * @return iterable<string, array{KeyPair, SignatureAlgorithm}>
     */
    public static function signers(): iterable
    {
        yield 'EC P-256' => [TestPki::signerEc256(), SignatureAlgorithm::ES256];
        yield 'EC P-384' => [TestPki::signerEc384(), SignatureAlgorithm::ES384];
        yield 'RSA' => [TestPki::signerRsa(), SignatureAlgorithm::RS256];
    }

    #[DataProvider('signers')]
    public function testAFullLtSignatureIsProducedAndValidates(KeyPair $keyPair, SignatureAlgorithm $expected): void
    {
        $this->useSigner($keyPair);
        $container = self::container();

        $signing = $this->signer->start($container, self::identity());
        self::assertSame($expected, $signing->dataToBeSigned->algorithm);

        $this->service->expectToSign($signing->dataToBeSigned->signedInfoCanonical);
        $result = $this->signer->poll($container, $signing);

        self::assertNotNull($result);
        self::assertSame(SignatureLevel::LT, $result->level);
        self::assertNotNull($result->timestampTime);
        self::assertNotNull($result->ocspProducedAt);
        self::assertSame([], $result->warnings);

        $report = $this->validate($result->container);
        self::assertSame(Indication::TotalPassed, $report, 'the signed container must validate');
    }

    /**
     * Mobile-ID DER-encodes ECDSA values; XML-DSig needs r‖s. Both forms must
     * finish the same signature.
     */
    #[DataProvider('ecdsaEncodings')]
    public function testEcdsaValuesAreAcceptedInEitherEncoding(bool $der): void
    {
        $this->service->derEncodeEcdsa = $der;
        $container = self::container();

        $signing = $this->signer->start($container, self::identity());
        $this->service->expectToSign($signing->dataToBeSigned->signedInfoCanonical);
        $result = $this->signer->poll($container, $signing);

        self::assertNotNull($result);
        self::assertSame(Indication::TotalPassed, $this->validate($result->container));
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function ecdsaEncodings(): iterable
    {
        yield 'DER, as the service sends it' => [true];
        yield 'raw r‖s' => [false];
    }

    public function testPollingReturnsNullWhileThePersonIsStillDeciding(): void
    {
        $this->service->runningPolls = 1;
        $container = self::container();
        $signing = $this->signer->start($container, self::identity());
        $this->service->expectToSign($signing->dataToBeSigned->signedInfoCanonical);

        self::assertNull($this->signer->poll($container, $signing));
        self::assertNotNull($this->signer->poll($container, $signing));
    }

    public function testBlockingSigningWaitsForThePerson(): void
    {
        $this->service->runningPolls = 3;
        $container = self::container();

        $signing = $this->signer->start($container, self::identity());
        $this->service->expectToSign($signing->dataToBeSigned->signedInfoCanonical);
        $result = $this->signer->complete($container, $signing, (new MobileIdPoller($this->client, new NullSleeper()))->wait($signing->session));

        self::assertSame(SignatureLevel::LT, $result->level);
    }

    public function testTheSessionSurvivesJsonBetweenTwoRequests(): void
    {
        $container = self::container();
        $signing = $this->signer->start($container, self::identity());
        $this->service->expectToSign($signing->dataToBeSigned->signedInfoCanonical);

        $restored = MobileIdSigningSession::fromJson(json_encode($signing, JSON_THROW_ON_ERROR));
        $result = $this->signer->poll($container, $restored);

        self::assertNotNull($result);
        self::assertSame(Indication::TotalPassed, $this->validate($result->container));
    }

    // --- refusals -----------------------------------------------------------

    public function testACancelledSignatureIsReportedAsCancelled(): void
    {
        $this->service->result = MobileIdResult::UserCancelled;
        $container = self::container();
        $signing = $this->signer->start($container, self::identity());

        try {
            $this->signer->poll($container, $signing);
            self::fail('Expected a MobileIdSessionException');
        } catch (MobileIdSessionException $exception) {
            self::assertSame(MobileIdResult::UserCancelled, $exception->result);
        }
    }

    public function testATamperedContainerCannotBeFinalized(): void
    {
        $container = self::container();
        $signing = $this->signer->start($container, self::identity());
        $this->service->expectToSign($signing->dataToBeSigned->signedInfoCanonical);

        $tampered = AsicContainer::create(DataFile::fromString('leping.txt', "Tere, vale leping!\n"));

        $this->expectException(SessionMismatchException::class);

        $this->signer->poll($tampered, $signing);
    }

    public function testACorruptSignatureValueIsRefusedBeforeAnyTimestampIsBought(): void
    {
        $this->service->corruptSignature = true;
        $container = self::container();
        $signing = $this->signer->start($container, self::identity());
        $this->service->expectToSign($signing->dataToBeSigned->signedInfoCanonical);

        $timestampsBefore = $this->fixture->tsa->requests;

        try {
            $this->signer->poll($container, $signing);
            self::fail('Expected the signature to be refused');
        } catch (\Throwable) {
            self::assertSame($timestampsBefore, $this->fixture->tsa->requests, 'no timestamp should be bought for a bad signature');
        }
    }

    public function testASignatureCanBeAppendedToAnAlreadySignedContainer(): void
    {
        $container = self::container();

        $first = $this->signer->start($container, self::identity());
        $this->service->expectToSign($first->dataToBeSigned->signedInfoCanonical);
        $once = $this->signer->poll($container, $first);
        self::assertNotNull($once);

        $second = $this->signer->start($once->container, self::identity());
        $this->service->expectToSign($second->dataToBeSigned->signedInfoCanonical);
        $twice = $this->signer->poll($once->container, $second);

        self::assertNotNull($twice);
        self::assertSame('META-INF/signatures0.xml', $once->signatureFileName);
        self::assertSame('META-INF/signatures1.xml', $twice->signatureFileName);
        self::assertSame(Indication::TotalPassed, $this->validate($twice->container));
    }

    public function testLevelBSkipsTheTimestampAndOcspEntirely(): void
    {
        $container = self::container();
        $signing = $this->signer->start($container, self::identity(), new SigningOptions(SignatureLevel::B));
        $this->service->expectToSign($signing->dataToBeSigned->signedInfoCanonical);

        $result = $this->signer->poll($container, $signing);

        self::assertNotNull($result);
        self::assertSame(SignatureLevel::B, $result->level);
        self::assertNull($result->timestampTime);
        self::assertSame(0, $this->fixture->tsa->requests);
    }

    /**
     * Validate with the library's own validator and report the verdict of the
     * last signature, with any complaint in the failure message.
     */
    private function validate(AsicContainer $container): Indication
    {
        $policy = new ValidationPolicy();
        $validator = new ContainerValidator(
            new SignatureValidator($this->fixture->trustStore, $policy),
            $this->fixture->clock,
            $policy,
        );

        $report = $validator->validate((new AsicWriter())->write($container), 'leping.asice');
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
