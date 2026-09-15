<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\SmartId;

use Allkiri\Crypto\HashAlgorithm;
use Allkiri\SmartId\CertificateLevel;
use Allkiri\SmartId\FlowType;
use Allkiri\SmartId\InteractionType;
use Allkiri\SmartId\RsaPssParameters;
use Allkiri\SmartId\SmartIdApiException;
use Allkiri\SmartId\SmartIdClient;
use Allkiri\SmartId\SmartIdEndResult;
use Allkiri\SmartId\SmartIdSessionStatusParser;
use Allkiri\Tests\Support\Pki\TestPki;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * A session status is unsigned JSON, and everything the authenticator and the
 * signer check afterwards is read from it here. These are the parser's own
 * rules, read directly rather than through a client and a mock service.
 */
#[CoversNothing]
final class SmartIdSessionStatusParserTest extends TestCase
{
    private const DOCUMENT_NUMBER = 'PNOEE-40504040001-MOCK-Q';

    /**
     * A successful RSASSA-PSS signature, as the service reports one, with any
     * part's fields replaced. Null stands for a field that is absent.
     *
     * @param array<string, mixed> $body       top-level fields
     * @param array<string, mixed> $result
     * @param array<string, mixed> $signature
     * @param array<string, mixed> $parameters the signature's PSS parameters
     * @param array<string, mixed> $maskGen    their mask generation function
     * @param array<string, mixed> $cert
     *
     * @return array<string, mixed>
     */
    private static function signed(
        array $body = [],
        array $result = [],
        array $signature = [],
        array $parameters = [],
        array $maskGen = [],
        array $cert = [],
    ): array {
        return [
            'state' => 'COMPLETE',
            'result' => ['endResult' => 'OK', 'documentNumber' => self::DOCUMENT_NUMBER, ...$result],
            'signatureProtocol' => 'ACSP_V2',
            'signature' => [
                'value' => base64_encode('the signature value'),
                'serverRandom' => 'c2VydmVyIHJhbmRvbQ==',
                'userChallenge' => 'dXNlciBjaGFsbGVuZ2U',
                'flowType' => 'QR',
                'signatureAlgorithm' => SmartIdClient::SIGNATURE_ALGORITHM_PSS,
                'signatureAlgorithmParameters' => [
                    'hashAlgorithm' => 'SHA-512',
                    'maskGenAlgorithm' => ['algorithm' => 'id-mgf1', 'parameters' => ['hashAlgorithm' => 'SHA-512'], ...$maskGen],
                    'saltLength' => 64,
                    'trailerField' => '0xbc',
                    ...$parameters,
                ],
                ...$signature,
            ],
            'cert' => ['value' => TestPki::signerRsaPerson()->certificate->base64(), 'certificateLevel' => 'QUALIFIED', ...$cert],
            'interactionTypeUsed' => 'displayTextAndPIN',
            'deviceIpAddress' => '192.0.2.10',
            ...$body,
        ];
    }

    public function testASessionThatHasNotFinishedIsRunning(): void
    {
        $status = SmartIdSessionStatusParser::parse(['state' => 'RUNNING']);

        self::assertTrue($status->isRunning());
        self::assertNull($status->result);
    }

    public function testASignatureIsReadInFull(): void
    {
        $status = SmartIdSessionStatusParser::parse(self::signed());

        self::assertTrue($status->isComplete());
        self::assertSame(SmartIdEndResult::Ok, $status->result);
        self::assertSame(self::DOCUMENT_NUMBER, $status->documentNumber?->value);
        self::assertSame('the signature value', $status->signatureValue);
        self::assertSame(SmartIdClient::SIGNATURE_ALGORITHM_PSS, $status->signatureAlgorithmName);
        self::assertEquals(new RsaPssParameters(HashAlgorithm::SHA512, HashAlgorithm::SHA512, 64, '0xbc'), $status->pssParameters);
        self::assertSame(TestPki::signerRsaPerson()->certificate->der(), $status->certificate?->der());
        self::assertSame(CertificateLevel::Qualified, $status->certificateLevel);
        self::assertSame('c2VydmVyIHJhbmRvbQ==', $status->serverRandom);
        self::assertSame('dXNlciBjaGFsbGVuZ2U', $status->userChallenge);
        self::assertSame(FlowType::Qr, $status->flowType);
        self::assertSame(InteractionType::DisplayTextAndPin, $status->interactionTypeUsed);
        self::assertNull($status->refusedInteraction);
        self::assertSame('192.0.2.10', $status->deviceIpAddress);
        self::assertSame('ACSP_V2', $status->signatureProtocol);
    }

    /**
     * @return iterable<string, array{string, HashAlgorithm}>
     */
    public static function hashSpellings(): iterable
    {
        yield 'SHA-256' => ['SHA-256', HashAlgorithm::SHA256];
        yield 'SHA256' => ['SHA256', HashAlgorithm::SHA256];
        yield 'sha-384' => ['sha-384', HashAlgorithm::SHA384];
        yield 'SHA512' => ['SHA512', HashAlgorithm::SHA512];
    }

    #[DataProvider('hashSpellings')]
    public function testAHashIsReadHoweverItIsSpelled(string $spelling, HashAlgorithm $hash): void
    {
        $status = SmartIdSessionStatusParser::parse(self::signed(
            parameters: ['hashAlgorithm' => $spelling],
            maskGen: ['algorithm' => 'MGF1', 'parameters' => ['hashAlgorithm' => $spelling]],
        ));

        $parameters = $status->pssParameters;
        self::assertNotNull($parameters);
        self::assertSame($hash, $parameters->hashAlgorithm);
        self::assertSame($hash, $parameters->maskHashAlgorithm);
    }

    public function testALegacyPkcs1SignatureCarriesNoPssParameters(): void
    {
        $body = self::signed();
        $body['signature'] = ['value' => base64_encode('the signature value'), 'signatureAlgorithm' => 'sha256WithRSAEncryption'];

        $status = SmartIdSessionStatusParser::parse($body);

        self::assertSame('sha256WithRSAEncryption', $status->signatureAlgorithmName);
        self::assertSame('the signature value', $status->signatureValue);
        self::assertNull($status->pssParameters);
    }

    /**
     * A certificate choice succeeds without signing anything, and the service
     * still sends a `signature` object carrying only the flow type.
     */
    public function testACertificateChoiceSignsNothing(): void
    {
        $body = self::signed();
        $body['signature'] = ['flowType' => 'Notification'];
        unset($body['interactionTypeUsed']);

        $status = SmartIdSessionStatusParser::parse($body);

        self::assertTrue($status->isOk());
        self::assertNull($status->signatureValue);
        self::assertNull($status->signatureAlgorithmName);
        self::assertNull($status->pssParameters);
        self::assertNull($status->serverRandom);
        self::assertNull($status->interactionTypeUsed);
        self::assertNotNull($status->certificate);
        self::assertSame(CertificateLevel::Qualified, $status->certificateLevel);
    }

    public function testSuccessNeedsOnlyTheAccountThatAnswered(): void
    {
        // Whether a signature or a certificate has to be there is for the flow
        // reading the status to decide, so the parser does not.
        $status = SmartIdSessionStatusParser::parse([
            'state' => 'COMPLETE',
            'result' => ['endResult' => 'OK', 'documentNumber' => self::DOCUMENT_NUMBER],
        ]);

        self::assertTrue($status->isOk());
        self::assertSame(self::DOCUMENT_NUMBER, $status->documentNumber?->value);
        self::assertNull($status->signatureValue);
        self::assertNull($status->certificate);
        self::assertNull($status->certificateLevel);
    }

    /**
     * @return iterable<string, array{SmartIdEndResult}>
     */
    public static function endResultsOtherThanOk(): iterable
    {
        foreach (SmartIdEndResult::cases() as $result) {
            if ($result !== SmartIdEndResult::Ok) {
                yield $result->value => [$result];
            }
        }
    }

    #[DataProvider('endResultsOtherThanOk')]
    public function testAnEndResultOtherThanOkCarriesNothingElse(SmartIdEndResult $result): void
    {
        // Even beside a signature and a certificate: a refusal is a refusal.
        $status = SmartIdSessionStatusParser::parse(self::signed(result: ['endResult' => $result->value]));

        self::assertTrue($status->isComplete());
        self::assertFalse($status->isOk());
        self::assertSame($result, $status->result);
        self::assertNull($status->documentNumber);
        self::assertNull($status->signatureValue);
        self::assertNull($status->certificate);
    }

    public function testTheRefusedDialogueIsNamedWhenItIsOneARequestCanAskFor(): void
    {
        $named = SmartIdSessionStatusParser::parse([
            'state' => 'COMPLETE',
            'result' => ['endResult' => 'USER_REFUSED_INTERACTION', 'details' => ['interaction' => 'confirmationMessage']],
        ]);
        self::assertSame(InteractionType::ConfirmationMessage, $named->refusedInteraction);

        // The service also answers with short forms no request uses.
        $unnamed = SmartIdSessionStatusParser::parse([
            'state' => 'COMPLETE',
            'result' => ['endResult' => 'USER_REFUSED_INTERACTION', 'details' => ['interaction' => 'verificationCodeChoice']],
        ]);
        self::assertSame(SmartIdEndResult::UserRefusedInteraction, $unnamed->result);
        self::assertNull($unnamed->refusedInteraction);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function malformed(): iterable
    {
        yield 'no state' => [self::signed(body: ['state' => null]), 'the session status has no state'];
        yield 'an empty state' => [self::signed(body: ['state' => '']), 'the session status has no state'];
        yield 'no result' => [self::signed(body: ['result' => null]), 'a complete session has no result'];
        yield 'a result that is not an object' => [self::signed(body: ['result' => 'OK']), 'a complete session has no result'];
        yield 'no end result' => [self::signed(result: ['endResult' => null]), 'a complete session has no end result'];
        yield 'an unknown end result' => [self::signed(result: ['endResult' => 'MAYBE']), 'the session reported an unknown end result "MAYBE"'];
        yield 'no account named' => [self::signed(result: ['documentNumber' => null]), 'the session succeeded without naming the account that answered'];
        yield 'an unusable account' => [self::signed(result: ['documentNumber' => 'nonsense']), 'the session reported an unusable document number "nonsense"'];
        yield 'a signature value that is not base64' => [self::signed(signature: ['value' => '!!!']), 'the signature value is not base64'];
        yield 'a signature without an algorithm' => [self::signed(signature: ['signatureAlgorithm' => null]), 'the session status is missing "signature.signatureAlgorithm"'];
        yield 'PSS without parameters' => [self::signed(signature: ['signatureAlgorithmParameters' => null]), 'a PSS signature arrived without its parameters'];
        yield 'PSS without a hash' => [self::signed(parameters: ['hashAlgorithm' => null]), 'the session status is missing "signatureAlgorithmParameters.hashAlgorithm"'];
        yield 'a hash no XAdES method describes' => [self::signed(parameters: ['hashAlgorithm' => 'SHA3-256']), 'the hash algorithm "SHA3-256" cannot be used in a XAdES signature'];
        yield 'no mask generation function' => [self::signed(parameters: ['maskGenAlgorithm' => null]), 'a PSS signature arrived without a mask generation algorithm'];
        yield 'a mask generation function without a name' => [self::signed(maskGen: ['algorithm' => null]), 'the session status is missing "maskGenAlgorithm.algorithm"'];
        yield 'a mask generation function other than MGF1' => [self::signed(maskGen: ['algorithm' => 'id-mgf2']), 'the mask generation algorithm is "id-mgf2", and only MGF1 is usable here'];
        yield 'MGF1 without parameters' => [self::signed(maskGen: ['parameters' => null]), 'the mask generation algorithm arrived without parameters'];
        yield 'MGF1 without a hash' => [self::signed(maskGen: ['parameters' => ['hashAlgorithm' => null]]), 'the session status is missing "maskGenAlgorithm.parameters.hashAlgorithm"'];
        yield 'MGF1 over a hash no XAdES method describes' => [self::signed(maskGen: ['parameters' => ['hashAlgorithm' => 'SHA3-512']]), 'the hash algorithm "SHA3-512" cannot be used in a XAdES signature'];
        yield 'a salt length that is not a number' => [self::signed(parameters: ['saltLength' => '64']), 'the PSS salt length is missing or not a number'];
        yield 'no trailer field' => [self::signed(parameters: ['trailerField' => null]), 'the session status is missing "signatureAlgorithmParameters.trailerField"'];
        yield 'a certificate without its value' => [self::signed(cert: ['value' => null]), 'the session status is missing "cert.value"'];
        yield 'a certificate that is not base64' => [self::signed(cert: ['value' => '!!!']), 'the certificate cannot be read: '];
        yield 'a certificate that is not a certificate' => [self::signed(cert: ['value' => base64_encode('not a certificate')]), 'the certificate cannot be read: '];
        yield 'a certificate without a level' => [self::signed(cert: ['certificateLevel' => null]), 'the session status is missing "cert.certificateLevel"'];
        yield 'an unknown certificate level' => [self::signed(cert: ['certificateLevel' => 'SUPREME']), 'the certificate level "SUPREME" is unknown'];
        yield 'an unknown flow' => [self::signed(signature: ['flowType' => 'Carrier pigeon']), 'the flow type "Carrier pigeon" is unknown'];
        yield 'an unknown dialogue' => [self::signed(body: ['interactionTypeUsed' => 'telepathy']), 'the app reported an unknown dialogue "telepathy"'];
    }

    /**
     * @param array<string, mixed> $body
     */
    #[DataProvider('malformed')]
    public function testAnythingUnusableIsRefusedAsMalformed(array $body, string $problem): void
    {
        try {
            SmartIdSessionStatusParser::parse($body);
            self::fail('Expected a SmartIdApiException');
        } catch (SmartIdApiException $exception) {
            self::assertSame(SmartIdApiException::REASON_MALFORMED_RESPONSE, $exception->reason);
            self::assertNull($exception->status);
            self::assertStringStartsWith('Smart-ID answered with something unusable: ' . $problem, $exception->getMessage());
        }
    }
}
