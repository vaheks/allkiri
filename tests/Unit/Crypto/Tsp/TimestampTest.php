<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Crypto\Tsp;

use Allkiri\Crypto\AlgorithmConstraints;
use Allkiri\Crypto\Asn1\Oids;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\KeyPair;
use Allkiri\Crypto\Tsp\PkiStatus;
use Allkiri\Crypto\Tsp\TimestampException;
use Allkiri\Crypto\Tsp\TimestampRequest;
use Allkiri\Crypto\Tsp\TimestampResponse;
use Allkiri\Crypto\Tsp\TimestampTokenVerifier;
use Allkiri\Crypto\Tsp\TimestampVerificationException;
use Allkiri\Crypto\Tsp\TspClient;
use Allkiri\Tests\Support\Clock\FrozenClock;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Tests\Support\Pki\MockTsa;
use Allkiri\Tests\Support\Pki\TestCertificates;
use Allkiri\Tests\Support\Pki\TestKey;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Tests\Support\Pki\TestSignatures;
use phpseclib3\Math\BigInteger;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class TimestampTest extends TestCase
{
    private const CAPTURED = __DIR__ . '/../../../fixtures/captured/';

    public function testCapturedDemoTokenVerifies(): void
    {
        $response = TimestampResponse::fromDer((string) file_get_contents(self::CAPTURED . 'demo-tsa-response.tsr'));
        $data = (string) file_get_contents(self::CAPTURED . 'demo-tsa-timestamped-data.bin');

        self::assertSame(PkiStatus::Granted, $response->status());
        $token = $response->token();
        self::assertNotNull($token);
        self::assertSame(Oids::SK_TSA_POLICY_QTST, $token->tstInfo()->policyOid);
        self::assertSame('2026-09-11T15:36:38+00:00', $token->genTime()->format(DATE_ATOM));
        self::assertSame(1, $token->tstInfo()->accuracySeconds);

        $result = (new TimestampTokenVerifier())->verify($token, HashAlgorithm::SHA256, HashAlgorithm::SHA256->digest($data), new BigInteger('E5185C4292EF3FBA', 16));

        self::assertSame('DEMO SK TIMESTAMPING UNIT 2025E', $result->tsaCertificate->commonName());
        self::assertSame($token->genTime(), $result->genTime());

        try {
            (new TimestampTokenVerifier())->verify($token, HashAlgorithm::SHA256, HashAlgorithm::SHA256->digest($data . 'x'));
            self::fail('wrong imprint accepted');
        } catch (TimestampVerificationException $e) {
            self::assertSame(TimestampVerificationException::REASON_IMPRINT, $e->reason);
        }
        try {
            (new TimestampTokenVerifier())->verify($token, HashAlgorithm::SHA256, HashAlgorithm::SHA256->digest($data), new BigInteger(42));
            self::fail('wrong nonce accepted');
        } catch (TimestampVerificationException $e) {
            self::assertSame(TimestampVerificationException::REASON_NONCE, $e->reason);
        }
    }

    public function testClientAgainstTheMockTsa(): void
    {
        $clock = new FrozenClock('2026-03-01T10:00:00Z');
        $http = new MockHttpClient();
        $tsa = MockTsa::register($http, $clock);
        $client = new TspClient($http, MockTsa::URL);

        $result = $client->timestamp('signature value bytes');

        self::assertSame('2026-03-01T10:00:00+00:00', $result->genTime()->format(DATE_ATOM));
        self::assertTrue($result->tsaCertificate->equals(TestPki::tsa()->certificate));
        self::assertSame(HashAlgorithm::SHA256->digest('signature value bytes'), $result->token->tstInfo()->messageImprint);
        self::assertSame(1, $tsa->requests);
        $sent = TimestampRequest::fromDer($http->lastRequest()->body ?? '');
        self::assertTrue($sent->certReq);
        self::assertNotNull($sent->nonce);
        self::assertSame('application/timestamp-query', $http->lastRequest()?->header('Content-Type'));
    }

    public function testEveryDefectOfTheTsaIsCaught(): void
    {
        $cases = [
            ['wrongImprint', TimestampVerificationException::REASON_IMPRINT],
            ['corruptSignature', TimestampVerificationException::REASON_BAD_SIGNATURE],
            ['includeCertificate', TimestampVerificationException::REASON_SIGNER_NOT_FOUND],
            ['omitNonce', TimestampVerificationException::REASON_NONCE],
        ];
        foreach ($cases as [$knob, $reason]) {
            $http = new MockHttpClient();
            $tsa = MockTsa::register($http, new FrozenClock());
            $tsa->{$knob} = $knob !== 'includeCertificate';
            try {
                (new TspClient($http, MockTsa::URL))->timestamp('x');
                self::fail("$knob went unnoticed");
            } catch (TimestampVerificationException $e) {
                self::assertSame($reason, $e->reason, $knob);
            }
        }
    }

    public function testRejectionAndHttpFailuresAreReported(): void
    {
        $http = new MockHttpClient();
        MockTsa::register($http, new FrozenClock())->reject = true;
        try {
            (new TspClient($http, MockTsa::URL))->timestamp('x');
            self::fail('rejection accepted');
        } catch (TimestampException $e) {
            self::assertSame('TIMESTAMP_REJECTED', $e->reason);
            self::assertStringContainsString('rejected by test TSA', $e->getMessage());
        }

        $http = (new MockHttpClient())->respond('http://tsa.down.test/', 503, 'text/plain', 'maintenance');
        try {
            (new TspClient($http, 'http://tsa.down.test/tsa'))->timestamp('x');
            self::fail('HTTP 503 accepted');
        } catch (TimestampException $e) {
            self::assertSame('TIMESTAMP_HTTP_STATUS', $e->reason);
        }
    }

    public function testTsaCertificateMustBeAllowedToTimestamp(): void
    {
        $http = new MockHttpClient();
        MockTsa::register($http, new FrozenClock(), TestPki::signerEc256());

        try {
            (new TspClient($http, MockTsa::URL))->timestamp('x');
            self::fail('non-TSA certificate accepted');
        } catch (TimestampVerificationException $e) {
            self::assertSame(TimestampVerificationException::REASON_TSA_KEY_USAGE, $e->reason);
        }

        // RFC 3161 §2.3: the purpose has to be marked critical as well.
        $http = new MockHttpClient();
        MockTsa::register($http, new FrozenClock(), TestCertificates::issue(TestPki::tsa(), ['id-at-commonName' => 'allkiri TSA With A Non-Critical Purpose'], ['id-ce-extKeyUsage' => [['id-kp-timeStamping'], false]]));

        try {
            (new TspClient($http, MockTsa::URL))->timestamp('x');
            self::fail('a TSA certificate with a non-critical purpose was accepted');
        } catch (TimestampVerificationException $e) {
            self::assertSame(TimestampVerificationException::REASON_TSA_KEY_USAGE, $e->reason);
            self::assertStringContainsString('not marked critical', $e->getMessage());
        }
    }

    public function testATokenSignedWithSha1IsNotAccepted(): void
    {
        $http = new MockHttpClient();
        MockTsa::register($http, new FrozenClock())->sign = TestSignatures::sha1(TestKey::fixture('tsa'));

        try {
            (new TspClient($http, MockTsa::URL))->timestamp('x');
            self::fail('a token signed with SHA-1 was accepted');
        } catch (TimestampVerificationException $e) {
            self::assertSame(TimestampVerificationException::REASON_ALGORITHM_NOT_ACCEPTED, $e->reason);
            self::assertSame('Token is signed with SHA-1, which is no longer accepted', $e->getMessage());
        }
    }

    public function testATsaWithASmallRsaKeyIsNotAccepted(): void
    {
        $http = new MockHttpClient();
        MockTsa::register($http, new FrozenClock(), self::rsaTsa(TestKey::rsa(1024)));

        try {
            (new TspClient($http, MockTsa::URL))->timestamp('x');
            self::fail('a 1024-bit TSA was accepted');
        } catch (TimestampVerificationException $e) {
            self::assertSame(TimestampVerificationException::REASON_ALGORITHM_NOT_ACCEPTED, $e->reason);
            self::assertStringContainsString('1024-bit', $e->getMessage());
        }
    }

    public function testTheCallerSetsTheKeySizeFloor(): void
    {
        $http = new MockHttpClient();
        MockTsa::register($http, new FrozenClock(), self::rsaTsa(TestPki::signerRsa()));
        (new TspClient($http, MockTsa::URL))->timestamp('a 2048-bit TSA meets the default');

        $this->expectException(TimestampVerificationException::class);
        $this->expectExceptionMessage('2048-bit');

        (new TspClient($http, MockTsa::URL, algorithmConstraints: new AlgorithmConstraints(4096)))->timestamp('x');
    }

    public function testRequestBuilderValidatesImprintLength(): void
    {
        $this->expectException(\Allkiri\Crypto\Asn1\Asn1Exception::class);
        TimestampRequest::build(HashAlgorithm::SHA256, 'too short');
    }

    /**
     * A timestamp authority certificate for an RSA key, with its purpose
     * marked critical as RFC 3161 requires.
     */
    private static function rsaTsa(KeyPair|TestKey $key): KeyPair
    {
        return TestCertificates::issue($key, ['id-at-commonName' => 'allkiri RSA TSA'], ['id-ce-extKeyUsage' => [['id-kp-timeStamping'], true]]);
    }
}
