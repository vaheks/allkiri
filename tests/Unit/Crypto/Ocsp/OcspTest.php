<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Crypto\Ocsp;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\KeyPair;
use Allkiri\Crypto\Ocsp\CertId;
use Allkiri\Crypto\Ocsp\CertificateRevokedException;
use Allkiri\Crypto\Ocsp\CertStatus;
use Allkiri\Crypto\Ocsp\NonceMode;
use Allkiri\Crypto\Ocsp\OcspClient;
use Allkiri\Crypto\Ocsp\OcspException;
use Allkiri\Crypto\Ocsp\OcspRequest;
use Allkiri\Crypto\Ocsp\OcspResponse;
use Allkiri\Crypto\Ocsp\OcspResponseStatus;
use Allkiri\Crypto\Ocsp\OcspResponseVerifier;
use Allkiri\Crypto\Ocsp\OcspVerificationException;
use Allkiri\Crypto\Ocsp\OcspVerificationOptions;
use Allkiri\Http\HttpRequest;
use Allkiri\Tests\Support\Clock\FrozenClock;
use Allkiri\Tests\Support\Crypto\DerPatch;
use Allkiri\Tests\Support\Crypto\FixedNonceGenerator;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Tests\Support\Pki\Asn1Encoders;
use Allkiri\Tests\Support\Pki\MockOcspResponder;
use Allkiri\Tests\Support\Pki\TestCertificates;
use Allkiri\Tests\Support\Pki\TestCertificateSignature;
use Allkiri\Tests\Support\Pki\TestKey;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Tests\Support\Pki\TestSignatures;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class OcspTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/../../../fixtures/';

    public function testCapturedDemoResponseVerifiesAgainstTheRealSkTestCa(): void
    {
        $subject = Certificate::fromPem((string) file_get_contents(self::FIXTURES . 'certs/TEST_ESTEID2018_signer_JOEORG.pem'));
        $issuer = Certificate::fromPem((string) file_get_contents(self::FIXTURES . 'certs/TEST_of_ESTEID2018.pem'));
        $request = OcspRequest::fromDer((string) file_get_contents(self::FIXTURES . 'captured/demo-ocsp-request.der'));
        $response = OcspResponse::fromDer((string) file_get_contents(self::FIXTURES . 'captured/demo-ocsp-response.ors'));

        self::assertTrue(CertId::for($subject, $issuer)->equals($request->certId), 'our CertID computation matches what we sent');
        self::assertNotNull($request->nonce);
        self::assertSame(OcspResponseStatus::Successful, $response->status());

        $basic = $response->basic();
        self::assertNotNull($basic);
        $result = (new OcspResponseVerifier())->verify(
            $response,
            $subject,
            $issuer,
            $request->nonce,
            $basic->producedAt(),
            new OcspVerificationOptions(NonceMode::Required, [], 300, null),
        );

        self::assertSame(CertStatus::Good, $result->status());
        self::assertSame('TEST of ESTEID2018 OCSP RESPONDER 202609', $result->responder->commonName());
        self::assertFalse($result->responderIsIssuer);
        self::assertFalse($result->responderFromTrustList);
        self::assertSame('2026-09-11T15:47:55+00:00', $result->producedAt()->format(DATE_ATOM));
        self::assertSame([], $result->warnings);

        $aia = OcspResponse::fromDer((string) file_get_contents(self::FIXTURES . 'captured/demo-aia-ocsp-response.ors'));
        $aiaResult = (new OcspResponseVerifier())->verify($aia, $subject, $issuer, null, $aia->basic()?->producedAt() ?? new \DateTimeImmutable(), OcspVerificationOptions::forValidation());
        self::assertSame('DEMO of ESTEID2018 OCSP RESPONDER 2026', $aiaResult->responder->commonName());
    }

    public function testClientFetchesAndVerifiesAgainstTheMockResponder(): void
    {
        $clock = new FrozenClock('2026-03-01T10:00:00Z');
        $http = new MockHttpClient();
        $responder = MockOcspResponder::register($http, $clock);
        $client = new OcspClient($http, $clock, nonces: new FixedNonceGenerator());
        $signer = TestPki::signerEc256();

        $result = $client->fetch($signer->certificate, TestPki::ca()->certificate);

        self::assertSame(MockOcspResponder::URL, $result->url);
        self::assertSame(CertStatus::Good, $result->verification->status());
        self::assertTrue($result->verification->responder->equals(TestPki::ocspResponder()->certificate));
        self::assertSame('2026-03-01T10:00:00+00:00', $result->verification->producedAt()->format(DATE_ATOM));
        self::assertSame(1, $responder->requests);
        $sent = OcspRequest::fromDer($http->lastRequest()->body ?? '');
        self::assertSame(32, \strlen((string) $sent->nonce));
        self::assertSame('application/ocsp-request', $http->lastRequest()?->header('Content-Type'));
        self::assertSame(OcspResponse::fromDer($result->der())->status(), OcspResponseStatus::Successful);
    }

    public function testEveryDefectOfTheResponderIsCaught(): void
    {
        $cases = [
            ['wrongNonce', OcspVerificationException::REASON_NONCE_MISMATCH],
            ['omitNonce', OcspVerificationException::REASON_NONCE_MISSING],
            ['wrongCertId', OcspVerificationException::REASON_NO_MATCHING_RESPONSE],
            ['corruptSignature', OcspVerificationException::REASON_BAD_SIGNATURE],
            ['includeCertificate', OcspVerificationException::REASON_RESPONDER_NOT_FOUND],
            ['unauthorizedStatus', OcspVerificationException::REASON_STATUS],
        ];
        foreach ($cases as [$knob, $reason]) {
            $clock = new FrozenClock('2026-03-01T10:00:00Z');
            $http = new MockHttpClient();
            $responder = MockOcspResponder::register($http, $clock);
            $responder->{$knob} = $knob !== 'includeCertificate';
            $client = new OcspClient($http, $clock);

            try {
                $client->fetch(TestPki::signerRsa()->certificate, TestPki::ca()->certificate);
                self::fail("$knob went unnoticed");
            } catch (OcspVerificationException $e) {
                self::assertSame($reason, $e->reason, $knob);
            }
        }
    }

    /**
     * A genuine answer signed with SHA-1 is refused, and only once nothing else
     * is wrong with it, so the reason names the real problem.
     */
    public function testAnAnswerSignedWithSha1IsNotAccepted(): void
    {
        $clock = new FrozenClock('2026-03-01T10:00:00Z');
        $http = new MockHttpClient();
        MockOcspResponder::register($http, $clock)->sign = TestSignatures::sha1(TestKey::fixture('ocsp'));

        try {
            (new OcspClient($http, $clock))->fetch(TestPki::signerEc256()->certificate, TestPki::ca()->certificate);
            self::fail('an answer signed with SHA-1 was accepted');
        } catch (OcspVerificationException $e) {
            self::assertSame(OcspVerificationException::REASON_ALGORITHM_NOT_ACCEPTED, $e->reason);
            self::assertSame('OCSP response is signed with SHA-1, which is no longer accepted', $e->getMessage());
        }
    }

    public function testADelegatedResponderCertificateIssuedWithSha1IsNotAccepted(): void
    {
        $responder = TestCertificates::issue(
            TestKey::fixture('ocsp'),
            ['id-at-commonName' => 'allkiri SHA-1 OCSP Responder'],
            ['id-ce-extKeyUsage' => [['id-kp-OCSPSigning'], false]],
            signature: TestCertificateSignature::Sha1,
        );
        $clock = new FrozenClock('2026-03-01T10:00:00Z');
        $http = new MockHttpClient();
        MockOcspResponder::register($http, $clock, $responder);

        try {
            (new OcspClient($http, $clock))->fetch(TestPki::signerEc256()->certificate, TestPki::ca()->certificate);
            self::fail('a responder certificate issued with SHA-1 was accepted');
        } catch (OcspVerificationException $e) {
            self::assertSame(OcspVerificationException::REASON_ALGORITHM_NOT_ACCEPTED, $e->reason);
            self::assertStringStartsWith('OCSP responder certificate is signed with SHA-1', $e->getMessage());
        }
    }

    public function testAResponderWithASmallRsaKeyIsNotAccepted(): void
    {
        $responder = TestCertificates::issue(
            TestKey::rsa(1024),
            ['id-at-commonName' => 'allkiri 1024-bit OCSP Responder'],
            ['id-ce-extKeyUsage' => [['id-kp-OCSPSigning'], false]],
        );
        $clock = new FrozenClock('2026-03-01T10:00:00Z');
        $http = new MockHttpClient();
        MockOcspResponder::register($http, $clock, $responder);

        try {
            (new OcspClient($http, $clock))->fetch(TestPki::signerEc256()->certificate, TestPki::ca()->certificate);
            self::fail('a 1024-bit responder was accepted');
        } catch (OcspVerificationException $e) {
            self::assertSame(OcspVerificationException::REASON_ALGORITHM_NOT_ACCEPTED, $e->reason);
            self::assertStringContainsString('1024-bit', $e->getMessage());
        }
    }

    /**
     * An algorithm allkiri cannot verify on the responder's certificate is a
     * reason like any other, not an exception from somewhere underneath.
     */
    public function testAResponderCertificateWithAnUnknownAlgorithmIsReportedAsUnsupported(): void
    {
        $responder = TestPki::ocspResponder();
        // sha224WithRSAEncryption, named in both places a certificate names its algorithm.
        $der = str_replace(
            Asn1Encoders::algorithmIdentifier('1.2.840.113549.1.1.11', true),
            Asn1Encoders::algorithmIdentifier('1.2.840.113549.1.1.14', true),
            $responder->certificate->der(),
            $count,
        );
        self::assertSame(2, $count);
        $clock = new FrozenClock('2026-03-01T10:00:00Z');
        $http = new MockHttpClient();
        MockOcspResponder::register($http, $clock, new KeyPair($responder->privateKey, Certificate::fromDer($der)));

        try {
            (new OcspClient($http, $clock))->fetch(TestPki::signerEc256()->certificate, TestPki::ca()->certificate);
            self::fail('a responder certificate with an unknown algorithm was accepted');
        } catch (OcspVerificationException $e) {
            self::assertSame(OcspVerificationException::REASON_UNSUPPORTED_ALGORITHM, $e->reason);
        }
    }

    /**
     * #27: a responder that signs with RSASSA-PSS, under a certificate the CA
     * also signed with it.
     */
    public function testAResponderSigningWithRsassaPssIsAccepted(): void
    {
        $responder = TestCertificates::issue(
            TestPki::signerRsa(),
            ['id-at-commonName' => 'allkiri PSS OCSP Responder'],
            ['id-ce-extKeyUsage' => [['id-kp-OCSPSigning'], false]],
            signature: TestCertificateSignature::Pss256,
        );
        $clock = new FrozenClock('2026-03-01T10:00:00Z');
        $http = new MockHttpClient();
        MockOcspResponder::register($http, $clock, $responder)->sign = TestSignatures::pss(TestKey::fixture('signer-rsa'));

        $result = (new OcspClient($http, $clock))->fetch(TestPki::signerEc256()->certificate, TestPki::ca()->certificate);

        self::assertSame(CertStatus::Good, $result->verification->status());
        self::assertSame('1.2.840.113549.1.1.10', $result->verification->basic->signatureAlgorithmOid());
    }

    /**
     * A key that cannot be read and a response that does not parse are a
     * reason like any other, never an exception from somewhere underneath.
     */
    public function testWhatCannotBeReadIsAReasonNotAnException(): void
    {
        $clock = new FrozenClock('2026-03-01T10:00:00Z');
        $responder = TestPki::ocspResponder();

        $http = new MockHttpClient();
        MockOcspResponder::register($http, $clock, new KeyPair($responder->privateKey, DerPatch::unreadableKey($responder->certificate)));
        try {
            (new OcspClient($http, $clock))->fetch(TestPki::signerEc256()->certificate, TestPki::ca()->certificate);
            self::fail('a responder certificate whose key cannot be read was accepted');
        } catch (OcspVerificationException $e) {
            self::assertSame(OcspVerificationException::REASON_UNSUPPORTED_ALGORITHM, $e->reason);
        }

        $request = OcspRequest::build(CertId::for(TestPki::signerEc256()->certificate, TestPki::ca()->certificate));
        $answer = (new MockOcspResponder($clock, $responder))->handle(HttpRequest::post(MockOcspResponder::URL, 'application/ocsp-request', $request->der))->body;
        $http = (new MockHttpClient())->respond(MockOcspResponder::URL, 200, 'application/ocsp-response', DerPatch::withoutCertificate($answer, $responder->certificate));
        try {
            (new OcspClient($http, $clock))->fetch(TestPki::signerEc256()->certificate, TestPki::ca()->certificate);
            self::fail('a response shipping something that is not a certificate was accepted');
        } catch (OcspException $e) {
            self::assertSame('OCSP_MALFORMED_RESPONSE', $e->reason);
            self::assertStringContainsString('Embedded certificate is malformed', $e->getMessage());
        }
    }

    public function testMissingNonceIsToleratedWhenNotRequired(): void
    {
        $clock = new FrozenClock('2026-03-01T10:00:00Z');
        $http = new MockHttpClient();
        MockOcspResponder::register($http, $clock)->omitNonce = true;
        $client = new OcspClient($http, $clock, options: new OcspVerificationOptions(NonceMode::IfPresent));

        self::assertSame(CertStatus::Good, $client->fetch(TestPki::signerEc384()->certificate, TestPki::ca()->certificate)->verification->status());
    }

    public function testRevokedAndUnknownAreFatalForSigning(): void
    {
        $clock = new FrozenClock('2026-03-01T10:00:00Z');
        $http = new MockHttpClient();
        $responder = MockOcspResponder::register($http, $clock);
        $client = new OcspClient($http, $clock);
        $ec = TestPki::signerEc256()->certificate;
        $rsa = TestPki::signerRsa()->certificate;
        $responder->revoke($ec->serialNumber(), new \DateTimeImmutable('2026-02-01T00:00:00Z'));
        $responder->unknown($rsa->serialNumber());

        try {
            $client->fetch($ec, TestPki::ca()->certificate);
            self::fail('revoked accepted');
        } catch (CertificateRevokedException $e) {
            self::assertSame(CertificateRevokedException::REASON_REVOKED, $e->reason);
            self::assertSame('2026-02-01T00:00:00+00:00', $e->revokedAt?->format(DATE_ATOM));
        }
        try {
            $client->fetch($rsa, TestPki::ca()->certificate);
            self::fail('unknown accepted');
        } catch (CertificateRevokedException $e) {
            self::assertSame(CertificateRevokedException::REASON_UNKNOWN, $e->reason);
        }
    }

    public function testTimeWindowsForSigningAndValidation(): void
    {
        $clock = new FrozenClock('2026-03-01T10:00:00Z');
        $http = new MockHttpClient();
        $responder = MockOcspResponder::register($http, $clock);
        $signing = new OcspClient($http, $clock, options: OcspVerificationOptions::forSigning());

        $responder->producedAtOffsetSeconds = 3600;
        try {
            $signing->fetch(TestPki::signerEc256()->certificate, TestPki::ca()->certificate);
            self::fail('future response accepted');
        } catch (OcspVerificationException $e) {
            self::assertSame(OcspVerificationException::REASON_TIME, $e->reason);
        }

        $responder->producedAtOffsetSeconds = -7200;
        try {
            $signing->fetch(TestPki::signerEc256()->certificate, TestPki::ca()->certificate);
            self::fail('stale response accepted');
        } catch (OcspVerificationException $e) {
            self::assertSame(OcspVerificationException::REASON_TIME, $e->reason);
        }

        // A two-hour-old response is fine when validating at the time it was produced.
        $validating = new OcspClient($http, new FrozenClock('2026-03-01T08:00:00Z'), options: OcspVerificationOptions::forValidation());
        self::assertSame(CertStatus::Good, $validating->fetch(TestPki::signerEc256()->certificate, TestPki::ca()->certificate)->verification->status());

        $responder->producedAtOffsetSeconds = 0;
        $responder->nextUpdateInSeconds = -1800;
        try {
            $signing->fetch(TestPki::signerEc256()->certificate, TestPki::ca()->certificate);
            self::fail('expired nextUpdate accepted for signing');
        } catch (OcspVerificationException $e) {
            self::assertSame(OcspVerificationException::REASON_TIME, $e->reason);
        }
    }

    public function testResponderUrlResolution(): void
    {
        $clock = new FrozenClock();
        $http = new MockHttpClient();
        $ca = TestPki::ca()->certificate;
        $withAia = TestPki::signerEc256()->certificate;

        self::assertSame(MockOcspResponder::URL, (new OcspClient($http, $clock))->responderUrl($withAia, $ca));
        self::assertSame('http://override.test/ocsp', (new OcspClient($http, $clock, urlOverrides: [$ca->subjectDn() => 'http://override.test/ocsp']))->responderUrl($withAia, $ca));
        self::assertSame('http://default.test/ocsp', (new OcspClient($http, $clock, defaultUrl: 'http://default.test/ocsp'))->responderUrl($ca, $ca), 'the CA cert has no AIA');

        $this->expectException(OcspException::class);
        (new OcspClient($http, $clock))->responderUrl($ca, $ca);
    }
}
