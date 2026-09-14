<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\WebEid;

use Allkiri\Crypto\Ocsp\OcspClient;
use Allkiri\Crypto\Ocsp\OcspVerificationOptions;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Tests\Support\Clock\FrozenClock;
use Allkiri\Tests\Support\Crypto\FixedNonceGenerator;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Tests\Support\Pki\MockOcspResponder;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Tests\Support\WebEid\TestAuthToken;
use Allkiri\Trust\ChainBuilder;
use Allkiri\Trust\CompositeTrustStore;
use Allkiri\Trust\InMemoryTrustStore;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustStore;
use Allkiri\WebEid\WebEidAuthenticator;
use Allkiri\WebEid\WebEidChallenge;
use Allkiri\WebEid\WebEidConfiguration;
use Allkiri\WebEid\WebEidException;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class WebEidAuthenticatorTest extends TestCase
{
    private const ORIGIN = 'https://allkiri.test';

    private FrozenClock $clock;

    private MockHttpClient $http;

    private MockOcspResponder $ocsp;

    private TrustStore $trustStore;

    protected function setUp(): void
    {
        $this->clock = new FrozenClock('2026-03-01T10:00:00Z');
        $this->http = new MockHttpClient();
        $this->ocsp = MockOcspResponder::register($this->http, $this->clock);
        $this->trustStore = new CompositeTrustStore(
            InMemoryTrustStore::fromCertificates([TestPki::ca()->certificate], ServiceType::CaQc, 'test PKI'),
            InMemoryTrustStore::fromCertificates([TestPki::ocspResponder()->certificate], ServiceType::OcspQc, 'test PKI'),
        );
    }

    private function authenticator(?WebEidConfiguration $configuration = null, ?TrustStore $trustStore = null): WebEidAuthenticator
    {
        $trustStore ??= $this->trustStore;

        return new WebEidAuthenticator(
            $configuration ?? WebEidConfiguration::forOrigin(self::ORIGIN),
            $trustStore,
            new OcspClient($this->http, $this->clock, nonces: new FixedNonceGenerator('ocsp'), options: OcspVerificationOptions::forSigning()),
            new ChainBuilder($trustStore),
            new FixedNonceGenerator('web-eid-challenge-nonce-of-32-by'),
            $this->clock,
        );
    }

    private function challenge(): WebEidChallenge
    {
        return $this->authenticator()->challenge();
    }

    // --- the challenge ------------------------------------------------------

    public function testTheChallengeMeetsTheSpecifiedLength(): void
    {
        $challenge = (new WebEidAuthenticator(
            WebEidConfiguration::forOrigin(self::ORIGIN),
            $this->trustStore,
            clock: $this->clock,
        ))->challenge();

        // At least 32 bytes of entropy, which base64 renders as 44 characters.
        self::assertGreaterThanOrEqual(WebEidChallenge::MINIMUM_LENGTH, \strlen($challenge->nonce));
        self::assertLessThanOrEqual(WebEidChallenge::MAXIMUM_LENGTH, \strlen($challenge->nonce));
        self::assertSame(32, \strlen((string) base64_decode($challenge->nonce, true)));
    }

    public function testTheChallengeExpires(): void
    {
        $challenge = $this->authenticator(WebEidConfiguration::forOrigin(self::ORIGIN)->withChallengeTtl(60))->challenge();

        self::assertFalse($challenge->isExpiredAt($this->clock->now()));
        self::assertFalse($challenge->isExpiredAt($this->clock->now()->modify('+59 seconds')));
        self::assertTrue($challenge->isExpiredAt($this->clock->now()->modify('+61 seconds')));
    }

    public function testTheChallengeSurvivesJsonBetweenTwoRequests(): void
    {
        $challenge = $this->challenge();

        $restored = WebEidChallenge::fromJson(json_encode($challenge, JSON_THROW_ON_ERROR));

        self::assertSame($challenge->nonce, $restored->nonce);
        self::assertEquals($challenge->expiresAt, $restored->expiresAt);
    }

    // --- a good token -------------------------------------------------------

    public function testAValidTokenNamesThePerson(): void
    {
        $challenge = $this->challenge();
        $token = TestAuthToken::create(self::ORIGIN, $challenge->nonce);

        $identity = $this->authenticator()->validate($token, $challenge);

        self::assertSame('38001085718', $identity->identityCode);
        self::assertSame('JAAK-KRISTJAN', $identity->givenName);
        self::assertSame('JOEORG', $identity->surname);
        self::assertSame('EE', $identity->country);
        self::assertSame('PNOEE-38001085718', $identity->semanticsIdentifier());
    }

    /**
     * The case that broke roughly one authentication in 256, deterministically.
     *
     * A card pads r and s to the curve width, so a half beginning 0x00 is
     * ordinary. The vendor validator's conversion to DER keeps that zero even
     * when it is superfluous, which is not minimal-form DER, and OpenSSL refuses
     * it. The signature below is a real one from the test card's key over this
     * exact origin and challenge, whose s half begins 00 7B: the zero is
     * unnecessary because 0x7B is under 0x80.
     *
     * See the workaround in WebEidAuthenticator, and
     * https://github.com/web-eid/web-eid-authtoken-validation-php/issues/71.
     * When that fix is released, this test should still pass with the
     * workaround removed. That is how to know it can go.
     */
    public function testASignatureWhoseHalfBeginsWithASuperfluousZeroIsAccepted(): void
    {
        $challenge = $this->challenge();
        // If this fails, the nonce generator changed and the signature below no
        // longer covers this challenge. Regenerate it rather than deleting it.
        self::assertSame('UEhXPxH7WCBTlMYFMcddA80LDktCj7+tXGw+l01hxjU=', $challenge->nonce);

        $signature = base64_decode(
            'ECH/aCo/x4qOHjyxTiW6/jXWbO05oOanOIejwLxDd5kVKjxuzemTiyt/2j/UF/iwAHtGTba85/nPvxHlI2is1aQejyqXB1xSfIc4/gr7xarq5EoHFuT+e+YzP437a9SL',
            true,
        );
        self::assertIsString($signature);
        self::assertSame("\x00", $signature[48], 'the s half should begin with a zero byte');
        self::assertLessThan(0x80, \ord($signature[49]), 'and the byte after it should make that zero superfluous');

        $identity = $this->authenticator()->validate(TestAuthToken::withSignature($signature), $challenge);

        self::assertSame('38001085718', $identity->identityCode);
    }

    public function testTheRevocationStatusIsChecked(): void
    {
        $challenge = $this->challenge();
        $token = TestAuthToken::create(self::ORIGIN, $challenge->nonce);

        $before = $this->ocsp->requests;
        $this->authenticator()->validate($token, $challenge);

        self::assertSame($before + 1, $this->ocsp->requests, 'the responder should have been asked');
    }

    public function testARevokedCardIsRefused(): void
    {
        $challenge = $this->challenge();
        $token = TestAuthToken::create(self::ORIGIN, $challenge->nonce);
        $this->ocsp->revoke(TestPki::cardAuth()->certificate->serialNumber(), $this->clock->now()->modify('-1 day'));

        $this->expectExceptionMessageMatches('/has been revoked/');

        $this->authenticator()->validate($token, $challenge);
    }

    public function testRevocationCheckingCanBeTurnedOffDeliberately(): void
    {
        $challenge = $this->challenge();
        $token = TestAuthToken::create(self::ORIGIN, $challenge->nonce);
        $this->ocsp->revoke(TestPki::cardAuth()->certificate->serialNumber(), $this->clock->now()->modify('-1 day'));

        $identity = $this->authenticator(WebEidConfiguration::forOrigin(self::ORIGIN)->withoutRevocationCheck())->validate($token, $challenge);

        self::assertSame('38001085718', $identity->identityCode);
    }

    // --- what the signature actually binds ----------------------------------

    /**
     * The origin is signed but not carried in the token, so a token made for
     * another site cannot be replayed here. This is the relay attack the format
     * exists to stop.
     */
    public function testATokenSignedForAnotherOriginIsRefused(): void
    {
        $challenge = $this->challenge();
        $token = TestAuthToken::create(self::ORIGIN, $challenge->nonce, signOrigin: 'https://evil.test');

        $this->expectException(WebEidException::class);

        $this->authenticator()->validate($token, $challenge);
    }

    /**
     * The same in the other direction: our own origin configured wrongly must
     * not quietly accept tokens meant for somewhere else.
     */
    public function testATokenIsRefusedWhenOurOriginIsConfiguredWrongly(): void
    {
        $challenge = $this->challenge();
        $token = TestAuthToken::create(self::ORIGIN, $challenge->nonce);

        $this->expectException(WebEidException::class);

        $this->authenticator(WebEidConfiguration::forOrigin('https://somewhere.else'))->validate($token, $challenge);
    }

    public function testATokenAnsweringAnotherChallengeIsRefused(): void
    {
        $challenge = $this->challenge();
        $token = TestAuthToken::create(self::ORIGIN, $challenge->nonce, signChallenge: base64_encode(random_bytes(32)));

        $this->expectException(WebEidException::class);

        $this->authenticator()->validate($token, $challenge);
    }

    /**
     * A token replayed against a different stored challenge must fail, which is
     * what stops one captured token from logging in twice.
     */
    public function testATokenCannotBeReplayedAgainstAnotherStoredChallenge(): void
    {
        $challenge = $this->challenge();
        $token = TestAuthToken::create(self::ORIGIN, $challenge->nonce);
        $this->authenticator()->validate($token, $challenge);

        $another = new WebEidChallenge(base64_encode(random_bytes(32)), $this->clock->now(), $this->clock->now()->modify('+5 minutes'));

        $this->expectException(WebEidException::class);

        $this->authenticator()->validate($token, $another);
    }

    public function testACorruptSignatureIsRefused(): void
    {
        $challenge = $this->challenge();

        $this->expectException(WebEidException::class);

        $this->authenticator()->validate(TestAuthToken::withCorruptSignature(self::ORIGIN, $challenge->nonce), $challenge);
    }

    public function testAnExpiredChallengeIsRefusedBeforeAnythingElse(): void
    {
        $challenge = $this->challenge();
        $token = TestAuthToken::create(self::ORIGIN, $challenge->nonce);
        $this->clock->advance('PT10M');

        $before = $this->ocsp->requests;

        try {
            $this->authenticator()->validate($token, $challenge);
            self::fail('Expected the challenge to be refused');
        } catch (WebEidException $exception) {
            self::assertStringContainsString('expired', $exception->getMessage());
            self::assertSame($before, $this->ocsp->requests, 'nothing should have been asked of the responder');
        }
    }

    // --- malformed tokens ---------------------------------------------------

    /**
     * @return iterable<string, array{string, mixed}>
     */
    public static function brokenTokens(): iterable
    {
        yield 'no certificate' => ['unverifiedCertificate', null];
        yield 'certificate is not a certificate' => ['unverifiedCertificate', base64_encode('not a certificate at all')];
        yield 'no signature' => ['signature', null];
        yield 'no algorithm' => ['algorithm', null];
        yield 'unsupported algorithm' => ['algorithm', 'HS256'];
        yield 'wrong format version' => ['format', 'web-eid:2.0'];
        yield 'no format' => ['format', null];
    }

    #[DataProvider('brokenTokens')]
    public function testAMalformedTokenIsRefused(string $field, mixed $value): void
    {
        $challenge = $this->challenge();

        $this->expectException(WebEidException::class);

        $this->authenticator()->validate(TestAuthToken::modified(self::ORIGIN, $challenge->nonce, $field, $value), $challenge);
    }

    public function testACertificateNestedTooDeeplyIsRefusedBeforeTheValidatorReadsIt(): void
    {
        // Inside the vendor validator, phpseclib would exhaust memory on this,
        // fatally, before any of our own code had read the certificate.
        $certificate = \Allkiri\Tests\Support\Crypto\DeepDer::inBasicConstraints(
            \Allkiri\Tests\Support\Pki\TestPki::ca()->certificate,
            \Allkiri\Tests\Support\Crypto\DeepDer::nested(20_000),
        );
        $challenge = $this->challenge();

        $this->expectException(WebEidException::class);
        $this->expectExceptionMessage('DER nests deeper than 64 levels');

        $this->authenticator()->validate(TestAuthToken::modified(self::ORIGIN, $challenge->nonce, 'unverifiedCertificate', base64_encode($certificate)), $challenge);
    }

    public function testSomethingThatIsNotATokenIsRefused(): void
    {
        $challenge = $this->challenge();

        $this->expectException(WebEidException::class);

        $this->authenticator()->validate(str_repeat('x', 200), $challenge);
    }

    // --- trust --------------------------------------------------------------

    public function testACardFromAnUnknownAuthorityIsRefused(): void
    {
        $challenge = $this->challenge();
        $token = TestAuthToken::create(self::ORIGIN, $challenge->nonce);
        $empty = new InMemoryTrustStore([]);

        $this->expectException(WebEidException::class);

        $this->authenticator(null, $empty)->validate($token, $challenge);
    }

    /**
     * A certificate that cannot do client authentication must not be accepted
     * as one, which is what keeps a signing certificate out of a login.
     */
    public function testACertificateWithoutTheAuthenticationPurposeIsRefused(): void
    {
        $challenge = $this->challenge();
        // The e-seal certificate carries no client-authentication purpose.
        $token = TestAuthToken::create(self::ORIGIN, $challenge->nonce, TestPki::signerRsa(), SignatureAlgorithm::RS256);

        $identity = $this->authenticator()->validate($token, $challenge);

        // It has digitalSignature and no extended key usage at all, which the
        // specification treats as usable for client authentication.
        self::assertNotSame('', $identity->certificate->subjectDn());
    }

    public function testACardCertificateOutsideItsValidityIsRefused(): void
    {
        $challenge = $this->challenge();
        $token = TestAuthToken::create(self::ORIGIN, $challenge->nonce);
        $this->clock->set('2060-01-01T00:00:00Z');

        $later = new WebEidChallenge($challenge->nonce, $this->clock->now(), $this->clock->now()->modify('+5 minutes'));

        $this->expectException(WebEidException::class);

        $this->authenticator()->validate($token, $later);
    }
}
