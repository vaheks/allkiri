<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\WebEid;

use Allkiri\Container\AsicContainer;
use Allkiri\Container\AsicWriter;
use Allkiri\Container\DataFile;
use Allkiri\Crypto\KeyPair;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Signing\PreparedSignatureExpiredException;
use Allkiri\Signing\SessionMismatchException;
use Allkiri\Signing\SignatureLevel;
use Allkiri\Signing\SigningOptions;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Tests\Support\SigningFixture;
use Allkiri\Validation\ContainerValidator;
use Allkiri\Validation\Report\Indication;
use Allkiri\Validation\SignatureValidator;
use Allkiri\Validation\ValidationPolicy;
use Allkiri\WebEid\CardAlgorithm;
use Allkiri\WebEid\WebEidException;
use Allkiri\WebEid\WebEidSigner;
use Allkiri\WebEid\WebEidSigningSession;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The ID-card signing flow, with this test standing in for the browser: it
 * reports what a card supports, then signs the digest with a test key exactly
 * as the card would.
 */
#[CoversNothing]
final class WebEidSignerTest extends TestCase
{
    private SigningFixture $fixture;

    private WebEidSigner $signer;

    protected function setUp(): void
    {
        $this->fixture = new SigningFixture();
        $this->signer = new WebEidSigner($this->fixture->signingService);
    }

    private static function container(): AsicContainer
    {
        return AsicContainer::create(DataFile::fromString('leping.txt', "Tere, allkiri!\n"));
    }

    /**
     * What an Estonian ID card reports: one elliptic-curve algorithm per hash.
     *
     * @return list<array<string, string>>
     */
    private static function cardAlgorithms(): array
    {
        return [
            ['cryptoAlgorithm' => 'ECC', 'hashFunction' => 'SHA-224', 'paddingScheme' => 'NONE'],
            ['cryptoAlgorithm' => 'ECC', 'hashFunction' => 'SHA-256', 'paddingScheme' => 'NONE'],
            ['cryptoAlgorithm' => 'ECC', 'hashFunction' => 'SHA-384', 'paddingScheme' => 'NONE'],
            ['cryptoAlgorithm' => 'ECC', 'hashFunction' => 'SHA-512', 'paddingScheme' => 'NONE'],
        ];
    }

    /**
     * The browser's half: sign the digest the way the card would.
     */
    private static function sign(WebEidSigningSession $session, KeyPair $keyPair): string
    {
        $algorithm = $session->dataToBeSigned->algorithm;

        return base64_encode($keyPair->privateKey->sign($algorithm, $session->dataToBeSigned->signedInfoCanonical));
    }

    // --- preparing ----------------------------------------------------------

    public function testTheStrongestHashTheCardSupportsIsChosen(): void
    {
        $card = TestPki::signerEc384();

        $session = $this->signer->prepare(self::container(), $card->certificate->base64(), self::cardAlgorithms());

        // The card's key is P-384 and it offers SHA-512, but the library picks
        // the strongest hash offered regardless of curve, which is what the
        // card itself will do.
        self::assertSame(SignatureAlgorithm::ES512, $session->dataToBeSigned->algorithm);
        self::assertSame('SHA-512', $session->algorithm->hashFunction);
        self::assertSame('NONE', $session->algorithm->paddingScheme);
    }

    public function testWhatTheBrowserNeedsIsExactlyTheHashAndItsName(): void
    {
        $card = TestPki::signerEc384();

        $session = $this->signer->prepare(self::container(), $card->certificate->base64(), self::cardAlgorithms());

        self::assertSame(
            ['hash' => $session->dataToBeSigned->digestBase64(), 'hashFunction' => 'SHA-512'],
            $session->forBrowser(),
        );
    }

    public function testAnExplicitAlgorithmIsHonouredWhenTheCardOffersIt(): void
    {
        $card = TestPki::signerEc384();

        $session = $this->signer->prepare(
            self::container(),
            $card->certificate->base64(),
            self::cardAlgorithms(),
            (new SigningOptions())->withAlgorithm(SignatureAlgorithm::ES384),
        );

        self::assertSame(SignatureAlgorithm::ES384, $session->dataToBeSigned->algorithm);
    }

    public function testAnAlgorithmTheCardDoesNotOfferIsRefusedUpFront(): void
    {
        $card = TestPki::signerEc384();

        $this->expectExceptionMessageMatches('/RS256 was requested but the card offers only/');

        $this->signer->prepare(
            self::container(),
            $card->certificate->base64(),
            self::cardAlgorithms(),
            (new SigningOptions())->withAlgorithm(SignatureAlgorithm::RS256),
        );
    }

    /**
     * An RSA card that offers both paddings should get PSS, which is the
     * stronger scheme and the one SK asks for elsewhere.
     */
    public function testPssIsPreferredOverPkcs1WhenBothAreOffered(): void
    {
        $card = TestPki::signerRsa();

        $session = $this->signer->prepare(self::container(), $card->certificate->base64(), [
            ['cryptoAlgorithm' => 'RSA', 'hashFunction' => 'SHA-256', 'paddingScheme' => 'PKCS1.5'],
            ['cryptoAlgorithm' => 'RSA', 'hashFunction' => 'SHA-256', 'paddingScheme' => 'PSS'],
        ]);

        self::assertSame(SignatureAlgorithm::PS256, $session->dataToBeSigned->algorithm);
    }

    /**
     * The algorithm has to match the key on the card, not merely be something
     * the card listed.
     */
    public function testAnAlgorithmForAnotherKeyTypeIsNotChosen(): void
    {
        $card = TestPki::signerRsa();

        $session = $this->signer->prepare(self::container(), $card->certificate->base64(), [
            ['cryptoAlgorithm' => 'ECC', 'hashFunction' => 'SHA-512', 'paddingScheme' => 'NONE'],
            ['cryptoAlgorithm' => 'RSA', 'hashFunction' => 'SHA-256', 'paddingScheme' => 'PKCS1.5'],
        ]);

        self::assertSame(SignatureAlgorithm::RS256, $session->dataToBeSigned->algorithm);
    }

    public function testACardOfferingNothingUsableIsReported(): void
    {
        $card = TestPki::signerEc384();

        $this->expectExceptionMessageMatches('/supports none of the signature algorithms/');

        // SHA-3 and SHA-224 have no signature method in the profile we produce.
        $this->signer->prepare(self::container(), $card->certificate->base64(), [
            ['cryptoAlgorithm' => 'ECC', 'hashFunction' => 'SHA3-256', 'paddingScheme' => 'NONE'],
            ['cryptoAlgorithm' => 'ECC', 'hashFunction' => 'SHA-224', 'paddingScheme' => 'NONE'],
        ]);
    }

    public function testAnEmptyAlgorithmListIsReported(): void
    {
        $this->expectExceptionMessageMatches('/reported no supported signature algorithms/');

        $this->signer->prepare(self::container(), TestPki::signerEc384()->certificate->base64(), []);
    }

    public function testACertificateThatIsNotOneIsReported(): void
    {
        $this->expectExceptionMessageMatches('/could not be read/');

        $this->signer->prepare(self::container(), base64_encode('not a certificate'), self::cardAlgorithms());
    }

    public function testAMalformedAlgorithmEntryIsReported(): void
    {
        $this->expectException(WebEidException::class);

        /** @var list<mixed> $algorithms */
        $algorithms = [['cryptoAlgorithm' => 'ECC', 'hashFunction' => 'SHA-256']];
        $this->signer->prepare(self::container(), TestPki::signerEc384()->certificate->base64(), $algorithms);
    }

    // --- completing ---------------------------------------------------------

    /**
     * @return iterable<string, array{KeyPair, list<array<string, string>>, SignatureAlgorithm}>
     */
    public static function cards(): iterable
    {
        yield 'ECDSA P-384, as Estonian cards use' => [
            TestPki::signerEc384(),
            [['cryptoAlgorithm' => 'ECC', 'hashFunction' => 'SHA-384', 'paddingScheme' => 'NONE']],
            SignatureAlgorithm::ES384,
        ];
        yield 'ECDSA P-256' => [
            TestPki::signerEc256(),
            [['cryptoAlgorithm' => 'ECC', 'hashFunction' => 'SHA-256', 'paddingScheme' => 'NONE']],
            SignatureAlgorithm::ES256,
        ];
        yield 'RSA with PKCS#1 v1.5' => [
            TestPki::signerRsa(),
            [['cryptoAlgorithm' => 'RSA', 'hashFunction' => 'SHA-256', 'paddingScheme' => 'PKCS1.5']],
            SignatureAlgorithm::RS256,
        ];
        yield 'RSA with PSS' => [
            TestPki::signerRsa(),
            [['cryptoAlgorithm' => 'RSA', 'hashFunction' => 'SHA-256', 'paddingScheme' => 'PSS']],
            SignatureAlgorithm::PS256,
        ];
    }

    /**
     * @param list<array<string, string>> $algorithms
     */
    #[DataProvider('cards')]
    public function testAFullLtSignatureIsProducedAndValidates(KeyPair $card, array $algorithms, SignatureAlgorithm $expected): void
    {
        $container = self::container();

        $session = $this->signer->prepare($container, $card->certificate->base64(), $algorithms);
        self::assertSame($expected, $session->dataToBeSigned->algorithm);

        $result = $this->signer->complete($container, $session, self::sign($session, $card), $session->algorithm);

        self::assertSame(SignatureLevel::LT, $result->level);
        self::assertNotNull($result->timestampTime);
        self::assertNotNull($result->ocspProducedAt);
        self::assertSame(Indication::TotalPassed, $this->validate((new AsicWriter())->write($result->container)));
    }

    public function testTheSessionSurvivesJsonBetweenTwoRequests(): void
    {
        $card = TestPki::signerEc384();
        $container = self::container();

        $session = $this->signer->prepare($container, $card->certificate->base64(), self::cardAlgorithms());
        $restored = WebEidSigningSession::fromJson(json_encode($session, JSON_THROW_ON_ERROR));

        self::assertSame($session->dataToBeSigned->digestBase64(), $restored->dataToBeSigned->digestBase64());
        self::assertTrue($session->algorithm->equals($restored->algorithm));

        $result = $this->signer->complete($container, $restored, self::sign($restored, $card));

        self::assertSame(Indication::TotalPassed, $this->validate((new AsicWriter())->write($result->container)));
    }

    /**
     * The card decides its own padding and reports it afterwards, so an answer
     * in a different algorithm would leave the container declaring a method it
     * does not use.
     */
    public function testAnAnswerInAnotherAlgorithmIsRefused(): void
    {
        $card = TestPki::signerEc384();
        $container = self::container();
        $session = $this->signer->prepare($container, $card->certificate->base64(), self::cardAlgorithms());

        $this->expectExceptionMessageMatches('/would declare the wrong method/');

        $this->signer->complete(
            $container,
            $session,
            self::sign($session, $card),
            new CardAlgorithm('ECC', 'SHA-256', 'NONE'),
        );
    }

    public function testASignatureFromAnotherKeyIsRefused(): void
    {
        $card = TestPki::signerEc384();
        $container = self::container();
        $session = $this->signer->prepare($container, $card->certificate->base64(), self::cardAlgorithms());

        $impostor = TestPki::cardAuth();

        $this->expectException(\Allkiri\Signing\InvalidSignatureValueException::class);

        $this->signer->complete($container, $session, self::sign($session, $impostor), $session->algorithm);
    }

    public function testASignatureThatIsNotBase64IsRefused(): void
    {
        $card = TestPki::signerEc384();
        $container = self::container();
        $session = $this->signer->prepare($container, $card->certificate->base64(), self::cardAlgorithms());

        $this->expectExceptionMessageMatches('/not base64/');

        $this->signer->complete($container, $session, '!!! not base64 !!!');
    }

    public function testATamperedContainerCannotBeFinalized(): void
    {
        $card = TestPki::signerEc384();
        $container = self::container();
        $session = $this->signer->prepare($container, $card->certificate->base64(), self::cardAlgorithms());

        $tampered = AsicContainer::create(DataFile::fromString('leping.txt', "Tere, vale leping!\n"));

        $this->expectException(SessionMismatchException::class);

        $this->signer->complete($tampered, $session, self::sign($session, $card));
    }

    /**
     * Card signing has no session timeout of its own, so this is the only
     * limit on how long the page may take.
     */
    public function testACardSignatureReturnedTooLateIsRefused(): void
    {
        $card = TestPki::signerEc384();
        $container = self::container();
        $session = $this->signer->prepare($container, $card->certificate->base64(), self::cardAlgorithms());
        $this->fixture->clock->advance('PT15M');

        try {
            $this->signer->complete($container, $session, self::sign($session, $card));
            self::fail('a card signature returned fifteen minutes later was finished');
        } catch (PreparedSignatureExpiredException) {
        }
        self::assertSame(0, $this->fixture->tsa->requests);
    }

    public function testASignatureCanBeAppendedToAnAlreadySignedContainer(): void
    {
        $card = TestPki::signerEc384();
        $container = self::container();

        $first = $this->signer->prepare($container, $card->certificate->base64(), self::cardAlgorithms());
        $once = $this->signer->complete($container, $first, self::sign($first, $card));

        $second = $this->signer->prepare($once->container, $card->certificate->base64(), self::cardAlgorithms());
        $twice = $this->signer->complete($once->container, $second, self::sign($second, $card));

        self::assertSame('META-INF/signatures0.xml', $once->signatureFileName);
        self::assertSame('META-INF/signatures1.xml', $twice->signatureFileName);
        self::assertSame(Indication::TotalPassed, $this->validate((new AsicWriter())->write($twice->container)));
    }

    // --- the algorithm vocabulary -------------------------------------------

    /**
     * @return iterable<string, array{string, string, string, SignatureAlgorithm|null}>
     */
    public static function algorithmMappings(): iterable
    {
        yield 'ECC SHA-256' => ['ECC', 'SHA-256', 'NONE', SignatureAlgorithm::ES256];
        yield 'ECC SHA-384' => ['ECC', 'SHA-384', 'NONE', SignatureAlgorithm::ES384];
        yield 'ECC SHA-512' => ['ECC', 'SHA-512', 'NONE', SignatureAlgorithm::ES512];
        yield 'RSA PKCS#1' => ['RSA', 'SHA-256', 'PKCS1.5', SignatureAlgorithm::RS256];
        yield 'RSA PSS' => ['RSA', 'SHA-512', 'PSS', SignatureAlgorithm::PS512];
        yield 'SHA-224 has no method' => ['ECC', 'SHA-224', 'NONE', null];
        yield 'SHA-3 has no method' => ['ECC', 'SHA3-256', 'NONE', null];
        yield 'RSA with no padding has no method' => ['RSA', 'SHA-256', 'NONE', null];
    }

    #[DataProvider('algorithmMappings')]
    public function testTheBrowserVocabularyMapsToSignatureMethods(string $crypto, string $hash, string $padding, ?SignatureAlgorithm $expected): void
    {
        self::assertSame($expected, (new CardAlgorithm($crypto, $hash, $padding))->signatureAlgorithm());
    }

    #[DataProvider('algorithmMappings')]
    public function testTheMappingGoesBothWays(string $crypto, string $hash, string $padding, ?SignatureAlgorithm $expected): void
    {
        if ($expected === null) {
            self::assertNull((new CardAlgorithm($crypto, $hash, $padding))->signatureAlgorithm());

            return;
        }

        self::assertTrue(
            CardAlgorithm::forSignatureAlgorithm($expected)->equals(new CardAlgorithm($crypto, $hash, $padding)),
        );
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
