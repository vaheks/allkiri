<?php

declare(strict_types=1);

namespace Allkiri\Tests\Integration;

use Allkiri\Allkiri;
use Allkiri\Clock\SystemClock;
use Allkiri\Config\Environment;
use Allkiri\Container\AsicContainer;
use Allkiri\Container\AsicWriter;
use Allkiri\Container\DataFile;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Signing\SignatureLevel;
use Allkiri\SmartId\CertificateLevel;
use Allkiri\SmartId\DocumentNumber;
use Allkiri\SmartId\Interaction;
use Allkiri\SmartId\Interactions;
use Allkiri\SmartId\SmartIdApiException;
use Allkiri\SmartId\SmartIdConfiguration;
use Allkiri\SmartId\SmartIdEndResult;
use Allkiri\SmartId\SmartIdPoller;
use Allkiri\SmartId\SmartIdSessionException;
use Allkiri\Validation\Report\Indication;
use Allkiri\Validation\Siva\SivaClient;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Smart-ID against SK's demo service, using their published test accounts.
 *
 * Only notification flows are exercised here. A device-link flow needs someone
 * to scan a QR code, and SK's own test suite drives that through a mock service
 * their client library knows about; the link construction is covered offline
 * instead, byte for byte.
 */
final class SmartIdDemoTest extends IntegrationTestCase
{
    /** An adult account that answers OK. */
    private const OK_DOCUMENT = 'PNOEE-50001029996-DEMO-Q';

    /** Issued under TEST of SK ID Solutions EID-Q 2024E. */
    private const OK_DOCUMENT_2024 = 'PNOEE-40504040001-DEM2-Q';

    private function configuration(): SmartIdConfiguration
    {
        return new SmartIdConfiguration(
            self::env('ALLKIRI_SMARTID_URL', SmartIdConfiguration::DEMO_URL),
            self::env('ALLKIRI_SMARTID_RP_UUID', SmartIdConfiguration::DEMO_RELYING_PARTY_UUID),
            self::env('ALLKIRI_SMARTID_RP_NAME', SmartIdConfiguration::DEMO_RELYING_PARTY_NAME),
            SmartIdConfiguration::SCHEME_DEMO,
            CertificateLevel::Qualified,
            sessionTimeoutSeconds: 90,
        );
    }

    private function allkiri(): Allkiri
    {
        $configuration = $this->configuration();

        return new Allkiri(Environment::demo(), self::http($configuration->httpTimeoutSeconds()), new SystemClock());
    }

    private static function interactions(): Interactions
    {
        return Interactions::of(Interaction::confirmationMessage('allkiri integration test'));
    }

    // --- certificates -------------------------------------------------------

    public function testACertificateCanBeFetchedWithNoInteraction(): void
    {
        $client = $this->allkiri()->smartIdClient($this->configuration());

        $certificate = $client->certificateByDocumentNumber(new DocumentNumber(self::OK_DOCUMENT));

        self::assertStringContainsString('50001029996', $certificate->certificate->subjectDn());
        self::assertTrue($certificate->certificate->isValidAt(new \DateTimeImmutable()));
        // Smart-ID keys are RSA throughout.
        self::assertSame('RSA', $certificate->certificate->keyType()->name);
        self::assertGreaterThanOrEqual(2048, $certificate->certificate->keyBits());
    }

    public function testAnUnknownAccountIsReportedAsSuch(): void
    {
        $client = $this->allkiri()->smartIdClient($this->configuration());

        try {
            $client->certificateByDocumentNumber(new DocumentNumber('PNOEE-00000000000-MOCK-Q'));
            self::fail('Expected a SmartIdApiException');
        } catch (SmartIdApiException $exception) {
            self::assertContains($exception->reason, [
                SmartIdApiException::REASON_ACCOUNT_NOT_FOUND,
                SmartIdApiException::REASON_NO_SUITABLE_ACCOUNT,
            ], $exception->getMessage());
        }
    }

    // --- authentication -----------------------------------------------------

    public function testAuthenticatingWithADemoAccountNamesThePerson(): void
    {
        $configuration = $this->configuration();
        $allkiri = $this->allkiri();
        $authenticator = $allkiri->smartIdAuthenticator($configuration);

        $session = $authenticator->startNotification(new DocumentNumber(self::OK_DOCUMENT), self::interactions());
        self::assertMatchesRegularExpression('/^\d{4}$/', (string) $session->verificationCode);

        $identity = $authenticator->authenticate($session, new SmartIdPoller($allkiri->smartIdClient($configuration)));

        self::assertSame('50001029996', $identity->identityCode);
        self::assertSame('EE', $identity->country);
        self::assertNotSame('', $identity->surname);
        self::assertNotSame('', $identity->givenName);
        self::assertSame('PNOEE-50001029996', $identity->semanticsIdentifier());
    }

    /**
     * A person can be addressed without knowing which of their accounts will
     * answer; the session reports the one that did.
     */
    public function testAuthenticatingByPersonRatherThanAccountAlsoWorks(): void
    {
        $configuration = $this->configuration();
        $allkiri = $this->allkiri();
        $authenticator = $allkiri->smartIdAuthenticator($configuration);

        $session = $authenticator->startNotification(
            (new DocumentNumber(self::OK_DOCUMENT))->semanticsIdentifier(),
            self::interactions(),
        );
        $status = (new SmartIdPoller($allkiri->smartIdClient($configuration)))->wait($session);

        self::assertTrue($status->isOk(), (string) $status->result?->value);
        self::assertSame(self::OK_DOCUMENT, $status->documentNumber?->value);

        $identity = $authenticator->complete($session, $status);
        self::assertSame('50001029996', $identity->identityCode);
    }

    // --- every published refusal --------------------------------------------

    /**
     * SK's published accounts, each documented to end one way.
     *
     * @return iterable<string, array{string, SmartIdEndResult}>
     */
    public static function refusingAccounts(): iterable
    {
        yield 'user refuses' => ['PNOEE-30403039917-MOCK-Q', SmartIdEndResult::UserRefused];
        yield 'user refuses the dialogue' => ['PNOEE-30403039946-MOCK-Q', SmartIdEndResult::UserRefusedInteraction];
        yield 'wrong verification code chosen' => ['PNOEE-30403039972-MOCK-Q', SmartIdEndResult::WrongVerificationCode];
        yield 'user does not react' => ['PNOEE-30403039983-MOCK-Q', SmartIdEndResult::Timeout];
    }

    #[DataProvider('refusingAccounts')]
    public function testEveryPublishedRefusalArrivesAsItsOwnResult(string $documentNumber, SmartIdEndResult $expected): void
    {
        $configuration = $this->configuration();
        $allkiri = $this->allkiri();
        $authenticator = $allkiri->smartIdAuthenticator($configuration);

        $session = $authenticator->startNotification(new DocumentNumber($documentNumber), self::interactions());

        try {
            (new SmartIdPoller($allkiri->smartIdClient($configuration)))->waitForSuccess($session);
            self::fail(\sprintf('%s was expected to end with %s', $documentNumber, $expected->value));
        } catch (SmartIdSessionException $exception) {
            self::assertSame($expected, $exception->result, $exception->getMessage());
            self::assertNotSame('', $exception->result->message());
        }
    }

    // --- signing ------------------------------------------------------------

    /**
     * @return iterable<string, array{string, HashAlgorithm, SignatureAlgorithm}>
     */
    public static function signingAccounts(): iterable
    {
        yield 'SHA-256' => [self::OK_DOCUMENT, HashAlgorithm::SHA256, SignatureAlgorithm::PS256];
        yield 'SHA-512' => [self::OK_DOCUMENT, HashAlgorithm::SHA512, SignatureAlgorithm::PS512];
        yield 'EID-Q 2024E account' => [self::OK_DOCUMENT_2024, HashAlgorithm::SHA256, SignatureAlgorithm::PS256];
    }

    /**
     * The Phase 3 gate: an RSA-PSS container signed by a demo account, accepted
     * by our own validator and by RIA's SiVa.
     */
    #[DataProvider('signingAccounts')]
    public function testAnRsaPssContainerIsAcceptedEverywhere(string $documentNumber, HashAlgorithm $hash, SignatureAlgorithm $expected): void
    {
        $configuration = $this->configuration()->withSigningHashAlgorithm($hash)->withCertificateLevel(CertificateLevel::Qscd);
        $allkiri = $this->allkiri();
        $signer = $allkiri->smartIdSigner($configuration);

        $container = AsicContainer::create(DataFile::fromString(
            'allkiri.txt',
            'Smart-ID interop check ' . date(DATE_ATOM),
        ));

        $signing = $signer->startNotification($container, new DocumentNumber($documentNumber), self::interactions());
        self::assertSame($expected, $signing->dataToBeSigned->algorithm);
        self::assertMatchesRegularExpression('/^\d{4}$/', (string) $signing->verificationCode());

        $status = (new SmartIdPoller($allkiri->smartIdClient($configuration)))->wait($signing->session);
        $result = $signer->complete($container, $signing, $status);

        self::assertSame(SignatureLevel::LT, $result->level);
        self::assertNotNull($result->timestampTime);
        self::assertNotNull($result->ocspProducedAt);

        $bytes = (new AsicWriter())->write($result->container);

        // Our own validator first.
        $report = $allkiri->validator()->validate($bytes, 'smart-id.asice');
        self::assertSame(
            Indication::TotalPassed,
            $report->signatures[0]->indication,
            implode('; ', array_map(static fn($f): string => $f->code . ': ' . $f->message, $report->signatures[0]->errors())),
        );

        // Then RIA's.
        $siva = new SivaClient(self::http(60), (string) Environment::demo()->sivaUrl);
        $sivaReport = self::askSiva($siva, $bytes, 'smart-id.asice');

        self::assertSame('ASiC-E', $sivaReport->signatureForm);
        self::assertSame('XAdES_BASELINE_LT', $sivaReport->signatures[0]->signatureFormat);
        self::assertSame(
            'TOTAL-PASSED',
            $sivaReport->signatures[0]->indication,
            implode('; ', $sivaReport->signatures[0]->errors),
        );

        self::saveArtefact(\sprintf('smart-id-%s-%s.asice', $hash->name(), substr($documentNumber, 6, 11)), $bytes);
    }

    /**
     * A signing certificate for an account we do not know yet costs one
     * interaction, after which the document number needs none.
     */
    public function testACertificateChoiceYieldsADocumentNumber(): void
    {
        $configuration = $this->configuration();
        $allkiri = $this->allkiri();
        $client = $allkiri->smartIdClient($configuration);

        $sessionId = $client->startNotificationCertificateChoice(
            (new DocumentNumber(self::OK_DOCUMENT))->semanticsIdentifier(),
            CertificateLevel::Qscd,
        );

        $deadline = time() + 90;
        do {
            $status = $client->sessionStatus($sessionId);
        } while ($status->isRunning() && time() < $deadline);

        self::assertTrue($status->isComplete(), 'the certificate choice never completed');
        // Nothing was signed, so the session carries an account and a
        // certificate and no signature at all.
        self::assertNull($status->signatureValue);

        $chosen = $allkiri->smartIdSigner($configuration)->completeCertificateChoice($status, CertificateLevel::Qscd);

        self::assertSame(self::OK_DOCUMENT, $chosen->documentNumber->value);
        self::assertStringContainsString('50001029996', $chosen->certificate->subjectDn());
    }

    private static function saveArtefact(string $name, string $bytes): void
    {
        $directory = getenv('ALLKIRI_ARTEFACTS');
        if (!\is_string($directory) || $directory === '' || !is_dir($directory)) {
            return;
        }
        file_put_contents(rtrim($directory, '/\\') . \DIRECTORY_SEPARATOR . $name, $bytes);
    }
}
