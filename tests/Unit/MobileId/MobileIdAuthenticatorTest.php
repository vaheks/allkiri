<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\MobileId;

use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\PrivateKey;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\MobileId\MobileIdAuthenticator;
use Allkiri\MobileId\MobileIdClient;
use Allkiri\MobileId\MobileIdException;
use Allkiri\MobileId\MobileIdIdentity;
use Allkiri\MobileId\MobileIdPoller;
use Allkiri\MobileId\MobileIdResult;
use Allkiri\MobileId\MobileIdSession;
use Allkiri\MobileId\MobileIdSessionException;
use Allkiri\MobileId\MobileIdSessionStatus;
use Allkiri\MobileId\VerificationCode;
use Allkiri\Tests\Support\Clock\FrozenClock;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Tests\Support\MobileId\MockMobileIdService;
use Allkiri\Tests\Support\MobileId\NullSleeper;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Trust\ChainBuilder;
use Allkiri\Trust\InMemoryTrustStore;
use Allkiri\Trust\ServiceType;
use phpseclib3\Crypt\EC;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class MobileIdAuthenticatorTest extends TestCase
{
    /** The identity code in the test PKI's EC signer certificates. */
    private const IDENTITY_CODE = '38001085718';

    private FrozenClock $clock;

    private MockHttpClient $http;

    private MockMobileIdService $service;

    private MobileIdClient $client;

    protected function setUp(): void
    {
        // Inside the validity of the committed test certificates.
        $this->clock = new FrozenClock('2026-03-01T10:00:00Z');
        $this->http = new MockHttpClient();
        $this->service = MockMobileIdService::register($this->http);
        $this->client = new MobileIdClient($this->service->configuration(), $this->http);
    }

    private function authenticator(?ChainBuilder $chainBuilder = null, HashAlgorithm $hash = HashAlgorithm::SHA256): MobileIdAuthenticator
    {
        return new MobileIdAuthenticator($this->client, $chainBuilder, $hash, clock: $this->clock);
    }

    private static function identity(): MobileIdIdentity
    {
        return new MobileIdIdentity('+37200000766', self::IDENTITY_CODE);
    }

    private function trustedChainBuilder(): ChainBuilder
    {
        return new ChainBuilder(InMemoryTrustStore::fromCertificates([TestPki::ca()->certificate], ServiceType::CaQc, 'test PKI'));
    }

    // --- starting -----------------------------------------------------------

    public function testStartingProducesTheCodeToShowThePerson(): void
    {
        $session = $this->authenticator()->start(self::identity());

        self::assertSame(MobileIdSession::TYPE_AUTHENTICATION, $session->type);
        self::assertMatchesRegularExpression('/^\d{4}$/', $session->verificationCode);
        // The code must be the one derived from the hash the phone will show.
        $encoded = $this->service->received[0]['hash'];
        self::assertIsString($encoded);
        $hash = base64_decode($encoded, true);
        self::assertIsString($hash);
        self::assertSame(VerificationCode::forHash($hash), $session->verificationCode);
    }

    public function testTheChallengeIsRandomAndItsDigestIsWhatIsSent(): void
    {
        $first = $this->authenticator()->start(self::identity());
        $second = $this->authenticator()->start(self::identity());

        self::assertNotSame($first->challenge, $second->challenge);
        self::assertSame(64, \strlen($first->challenge));
        self::assertSame(
            base64_encode(hash('sha256', $first->challenge, true)),
            $this->service->received[0]['hash'],
        );
    }

    /**
     * @return iterable<string, array{HashAlgorithm, string}>
     */
    public static function hashAlgorithms(): iterable
    {
        yield 'sha256' => [HashAlgorithm::SHA256, 'SHA256'];
        yield 'sha384' => [HashAlgorithm::SHA384, 'SHA384'];
        yield 'sha512' => [HashAlgorithm::SHA512, 'SHA512'];
    }

    #[DataProvider('hashAlgorithms')]
    public function testEveryAcceptedHashAlgorithmWorksEndToEnd(HashAlgorithm $algorithm, string $expectedName): void
    {
        $authenticator = $this->authenticator($this->trustedChainBuilder(), $algorithm);
        $session = $authenticator->start(self::identity());
        $this->service->expectToSign($session->challenge);

        $identity = $authenticator->poll($session);

        self::assertSame($expectedName, $this->service->received[0]['hashType']);
        self::assertNotNull($identity);
        self::assertSame(self::IDENTITY_CODE, $identity->identityCode);
    }

    // --- completing ---------------------------------------------------------

    public function testASuccessfulAuthenticationNamesThePerson(): void
    {
        $authenticator = $this->authenticator($this->trustedChainBuilder());
        $session = $authenticator->start(self::identity());
        $this->service->expectToSign($session->challenge);

        $identity = $authenticator->poll($session);

        self::assertNotNull($identity);
        self::assertSame(self::IDENTITY_CODE, $identity->identityCode);
        self::assertSame('TESTER', $identity->givenName);
        self::assertSame('ALLKIRI', $identity->surname);
        self::assertSame('EE', $identity->country);
        self::assertSame('TESTER ALLKIRI', $identity->fullName());
        self::assertSame('PNOEE-38001085718', $identity->semanticsIdentifier());
    }

    public function testPollingReturnsNullWhileThePersonIsStillDeciding(): void
    {
        $this->service->runningPolls = 1;
        $authenticator = $this->authenticator();
        $session = $authenticator->start(self::identity());
        $this->service->expectToSign($session->challenge);

        self::assertNull($authenticator->poll($session));
        self::assertNotNull($authenticator->poll($session));
    }

    public function testBlockingAuthenticationWaitsForThePerson(): void
    {
        $this->service->runningPolls = 2;
        $authenticator = $this->authenticator($this->trustedChainBuilder());

        // The challenge is only known once the session starts, so the mock is
        // told through the same hash the poller will see.
        $session = $authenticator->start(self::identity());
        $this->service->expectToSign($session->challenge);
        $identity = $authenticator->complete($session, (new MobileIdPoller($this->client, new NullSleeper()))->wait($session));

        self::assertSame(self::IDENTITY_CODE, $identity->identityCode);
    }

    // --- refusals -----------------------------------------------------------

    public function testACancelledSessionIsReportedAsCancelled(): void
    {
        $this->service->result = MobileIdResult::UserCancelled;
        $authenticator = $this->authenticator();
        $session = $authenticator->start(self::identity());

        try {
            $authenticator->poll($session);
            self::fail('Expected a MobileIdSessionException');
        } catch (MobileIdSessionException $exception) {
            self::assertSame(MobileIdResult::UserCancelled, $exception->result);
            self::assertTrue($exception->result->isWorthRetrying());
        }
    }

    /**
     * The whole point of the challenge: a signature over anything else proves
     * nothing, even though the service said OK.
     */
    /**
     * The whole point of the challenge: a signature over anything else proves
     * nothing, even though the service said OK. This is what a replayed or
     * substituted session looks like.
     */
    public function testASignatureOverTheWrongChallengeIsRefused(): void
    {
        $authenticator = $this->authenticator();
        $session = $authenticator->start(self::identity());

        $signer = TestPki::signerEc256();
        $status = new MobileIdSessionStatus(
            MobileIdSessionStatus::STATE_COMPLETE,
            MobileIdResult::Ok,
            $signer->privateKey->sign(SignatureAlgorithm::ES256, 'a challenge from some other session'),
            SignatureAlgorithm::ES256,
            $signer->certificate,
        );

        $this->expectExceptionMessageMatches('/does not match the challenge/');

        $authenticator->complete($session, $status);
    }

    /**
     * The certificate is the only thing that says who signed, so a signature
     * made by a different key must not pass just because it verifies against
     * its own certificate.
     */
    public function testASignatureFromAnotherKeyIsRefused(): void
    {
        $authenticator = $this->authenticator();
        $session = $authenticator->start(self::identity());

        // Another key on the same curve, so the value is the right size and
        // only the mathematics can reject it.
        $impostor = PrivateKey::fromPem(EC::createKey('secp256r1')->toString('PKCS8'));

        $status = new MobileIdSessionStatus(
            MobileIdSessionStatus::STATE_COMPLETE,
            MobileIdResult::Ok,
            $impostor->sign(SignatureAlgorithm::ES256, $session->challenge),
            SignatureAlgorithm::ES256,
            TestPki::signerEc256()->certificate,
        );

        $this->expectExceptionMessageMatches('/does not match the challenge/');

        $authenticator->complete($session, $status);
    }

    public function testAnEcdsaValueOfTheWrongSizeIsRefused(): void
    {
        $authenticator = $this->authenticator();
        $session = $authenticator->start(self::identity());

        $status = new MobileIdSessionStatus(
            MobileIdSessionStatus::STATE_COMPLETE,
            MobileIdResult::Ok,
            TestPki::signerEc384()->privateKey->sign(SignatureAlgorithm::ES384, $session->challenge),
            null,
            TestPki::signerEc256()->certificate,
        );

        $this->expectExceptionMessageMatches('/must be 64 bytes, got 96/');

        $authenticator->complete($session, $status);
    }

    public function testAnAlgorithmOtherThanTheOneAskedForIsRefused(): void
    {
        $authenticator = $this->authenticator();
        $session = $authenticator->start(self::identity());
        $signer = TestPki::signerEc256();

        $status = new MobileIdSessionStatus(
            MobileIdSessionStatus::STATE_COMPLETE,
            MobileIdResult::Ok,
            $signer->privateKey->sign(SignatureAlgorithm::ES384, $session->challenge),
            SignatureAlgorithm::ES384,
            $signer->certificate,
        );

        $this->expectExceptionMessageMatches('/signed with ES384 but the request asked for ES256/');

        $authenticator->complete($session, $status);
    }

    public function testACorruptSignatureIsRefused(): void
    {
        $this->service->corruptSignature = true;
        $authenticator = $this->authenticator();
        $session = $authenticator->start(self::identity());
        $this->service->expectToSign($session->challenge);

        $this->expectException(MobileIdException::class);

        $authenticator->poll($session);
    }

    public function testAnAnswerForAnotherPersonIsRefused(): void
    {
        $authenticator = $this->authenticator();
        // The service answers for the test certificate's person, not this one.
        $session = $authenticator->start(new MobileIdIdentity('+37200000766', '60001019906'));
        $this->service->expectToSign($session->challenge);

        $this->expectExceptionMessageMatches('/but the session was started for 60001019906/');

        $authenticator->poll($session);
    }

    public function testACertificateOutsideItsValidityIsRefused(): void
    {
        $this->clock->set('2060-01-01T00:00:00Z');
        $authenticator = $this->authenticator();
        $session = $authenticator->start(self::identity());
        $this->service->expectToSign($session->challenge);

        $this->expectExceptionMessageMatches('/not valid at this moment/');

        $authenticator->poll($session);
    }

    public function testACertificateFromAnUnknownAuthorityIsRefused(): void
    {
        $empty = new ChainBuilder(new InMemoryTrustStore([]));
        $authenticator = $this->authenticator($empty);
        $session = $authenticator->start(self::identity());
        $this->service->expectToSign($session->challenge);

        $this->expectExceptionMessageMatches('/does not chain to a trusted authority/');

        $authenticator->poll($session);
    }

    public function testASigningSessionCannotBeCompletedAsAnAuthentication(): void
    {
        $signing = new MobileIdSession('abc', MobileIdSession::TYPE_SIGNATURE, '1234', self::identity());
        $this->service->expectToSign('x');
        $sessionId = $this->client->startAuthentication(self::identity(), hash('sha256', 'x', true), HashAlgorithm::SHA256);
        $status = $this->client->status(MobileIdSession::TYPE_AUTHENTICATION, $sessionId);

        $this->expectExceptionMessageMatches('/signing session, not an authentication/');

        $this->authenticator()->complete($signing, $status);
    }
}
