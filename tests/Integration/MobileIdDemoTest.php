<?php

declare(strict_types=1);

namespace Allkiri\Tests\Integration;

use Allkiri\Allkiri;
use Allkiri\Clock\SystemClock;
use Allkiri\Config\Environment;
use Allkiri\Container\AsicContainer;
use Allkiri\Container\AsicWriter;
use Allkiri\Container\DataFile;
use Allkiri\MobileId\CertificateNotFoundException;
use Allkiri\MobileId\MobileIdConfiguration;
use Allkiri\MobileId\MobileIdIdentity;
use Allkiri\MobileId\MobileIdPoller;
use Allkiri\MobileId\MobileIdResult;
use Allkiri\MobileId\MobileIdSessionException;
use Allkiri\Signing\SignatureLevel;
use Allkiri\Validation\Report\Indication;
use Allkiri\Validation\Siva\SivaClient;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Mobile-ID against SK's demo service, using their published test numbers.
 *
 * Every one of these numbers is documented to produce a particular outcome, so
 * this is the one place where the mapping from the wire to our typed results
 * is checked against the real thing rather than against a mock.
 *
 * The positive numbers take between three and fifteen seconds to answer, which
 * is why these are integration tests and not part of `composer test`.
 */
final class MobileIdDemoTest extends IntegrationTestCase
{
    /** ECC and RSA certificate pair; the ECC one is always used. Answers in ~7 s. */
    private const OK_PHONE = '+37200000766';
    private const OK_CODE = '60001019906';

    /** A single RSA pair, so the RSA path is exercised too. Answers in ~15 s. */
    private const RSA_PHONE = '+37200001566';
    private const RSA_CODE = '39901019992';

    private function configuration(): MobileIdConfiguration
    {
        return new MobileIdConfiguration(
            self::env('ALLKIRI_MID_URL', MobileIdConfiguration::DEMO_URL),
            self::env('ALLKIRI_MID_UUID', MobileIdConfiguration::DEMO_RELYING_PARTY_UUID),
            self::env('ALLKIRI_MID_NAME', MobileIdConfiguration::DEMO_RELYING_PARTY_NAME),
            displayText: 'allkiri test',
            // The demo numbers answer well inside this, and a failing one
            // should not hold the suite for two minutes.
            sessionTimeoutSeconds: 90,
        );
    }

    private function allkiri(): Allkiri
    {
        $configuration = $this->configuration();
        $http = self::http($configuration->httpTimeoutSeconds());

        return new Allkiri(Environment::demo(), $http, new SystemClock());
    }

    // --- certificate --------------------------------------------------------

    public function testTheDemoNumbersCertificateCanBeFetched(): void
    {
        $client = $this->allkiri()->mobileIdClient($this->configuration());

        $certificate = $client->certificate(new MobileIdIdentity(self::OK_PHONE, self::OK_CODE));

        self::assertStringContainsString(self::OK_CODE, $certificate->subjectDn());
        self::assertTrue($certificate->isValidAt(new \DateTimeImmutable()), 'the demo certificate should be current');
        // Documented as an ECC prime256v1 pair, always preferred over the RSA one.
        self::assertSame('secp256r1', $certificate->curveName());
    }

    public function testANumberWithoutMobileIdIsReportedAsSuch(): void
    {
        $client = $this->allkiri()->mobileIdClient($this->configuration());

        $this->expectException(CertificateNotFoundException::class);

        $client->certificate(new MobileIdIdentity('+37200000266', '60001019939'));
    }

    // --- authentication -----------------------------------------------------

    public function testAuthenticatingWithTheDemoNumberNamesThePerson(): void
    {
        $allkiri = $this->allkiri();
        $authenticator = $allkiri->mobileIdAuthenticator($this->configuration());

        $session = $authenticator->start(new MobileIdIdentity(self::OK_PHONE, self::OK_CODE));
        self::assertMatchesRegularExpression('/^\d{4}$/', $session->verificationCode);

        $identity = $authenticator->complete(
            $session,
            (new MobileIdPoller($allkiri->mobileIdClient($this->configuration())))->wait($session),
        );

        self::assertSame(self::OK_CODE, $identity->identityCode);
        self::assertSame('EE', $identity->country);
        self::assertNotSame('', $identity->surname);
        self::assertNotSame('', $identity->givenName);
        self::assertSame('PNOEE-' . self::OK_CODE, $identity->semanticsIdentifier());
    }

    // --- every published failure --------------------------------------------

    /**
     * SK's published numbers, each documented to produce one outcome.
     *
     * @return iterable<string, array{string, string, MobileIdResult}>
     */
    public static function failingNumbers(): iterable
    {
        yield 'no active certificates' => ['+37200000266', '60001019939', MobileIdResult::NotMidClient];
        yield 'request could not be delivered' => ['+37207110066', '60001019947', MobileIdResult::DeliveryError];
        yield 'user cancels' => ['+37201100266', '60001019950', MobileIdResult::UserCancelled];
        yield 'signature does not match' => ['+37200000666', '60001019961', MobileIdResult::SignatureHashMismatch];
        yield 'SIM application error' => ['+37201200266', '60001019972', MobileIdResult::SimError];
        yield 'phone out of coverage' => ['+37213100266', '60001019983', MobileIdResult::PhoneAbsent];
        yield 'user does not react' => ['+37266000266', '50001018908', MobileIdResult::Timeout];
    }

    #[DataProvider('failingNumbers')]
    public function testEveryPublishedFailureArrivesAsItsOwnResult(string $phone, string $code, MobileIdResult $expected): void
    {
        $configuration = $this->configuration();
        $allkiri = $this->allkiri();
        $client = $allkiri->mobileIdClient($configuration);
        $identity = new MobileIdIdentity($phone, $code);

        // NOT_MID_CLIENT is decided before any session starts: the person has
        // no certificate to sign with.
        if ($expected === MobileIdResult::NotMidClient) {
            $this->expectException(CertificateNotFoundException::class);
            $client->certificate($identity);

            return;
        }

        $authenticator = $allkiri->mobileIdAuthenticator($configuration);
        $session = $authenticator->start($identity);

        try {
            (new MobileIdPoller($client))->wait($session);
            self::fail(\sprintf('%s was expected to fail with %s', $phone, $expected->value));
        } catch (MobileIdSessionException $exception) {
            self::assertSame($expected, $exception->result, $exception->getMessage());
            self::assertNotSame('', $exception->result->message());
        }
    }

    // --- signing ------------------------------------------------------------

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function signingNumbers(): iterable
    {
        yield 'ECC' => [self::OK_PHONE, self::OK_CODE];
        yield 'RSA' => [self::RSA_PHONE, self::RSA_CODE];
    }

    /**
     * The Phase 2 gate: a container signed by a demo number, accepted by our
     * own validator and by RIA's SiVa.
     *
     * These certificates are issued by CAs the Estonian test trusted list
     * carries, so unlike our own test CA this reaches TOTAL-PASSED.
     */
    #[DataProvider('signingNumbers')]
    public function testAContainerSignedByADemoNumberIsAcceptedEverywhere(string $phone, string $code): void
    {
        $configuration = $this->configuration();
        $allkiri = $this->allkiri();
        $signer = $allkiri->mobileIdSigner($configuration);
        $identity = new MobileIdIdentity($phone, $code);

        $container = AsicContainer::create(DataFile::fromString(
            'allkiri.txt',
            'Mobile-ID interop check ' . date(DATE_ATOM),
        ));

        $signing = $signer->start($container, $identity);
        self::assertMatchesRegularExpression('/^\d{4}$/', $signing->verificationCode());

        $status = (new MobileIdPoller($allkiri->mobileIdClient($configuration)))->wait($signing->session);
        $result = $signer->complete($container, $signing, $status);

        self::assertSame(SignatureLevel::LT, $result->level);
        self::assertNotNull($result->timestampTime);
        self::assertNotNull($result->ocspProducedAt);

        $bytes = (new AsicWriter())->write($result->container);

        // Our own validator first.
        $report = $allkiri->validator()->validate($bytes, 'mobile-id.asice');
        self::assertSame(
            Indication::TotalPassed,
            $report->signatures[0]->indication,
            implode('; ', array_map(static fn($f): string => $f->code . ': ' . $f->message, $report->signatures[0]->errors())),
        );

        // Then RIA's.
        $siva = new SivaClient(self::http(60), (string) Environment::demo()->sivaUrl);
        $sivaReport = $siva->validate($bytes, 'mobile-id.asice');

        self::assertSame('ASiC-E', $sivaReport->signatureForm);
        self::assertSame('XAdES_BASELINE_LT', $sivaReport->signatures[0]->signatureFormat);
        self::assertSame(
            'TOTAL-PASSED',
            $sivaReport->signatures[0]->indication,
            implode('; ', $sivaReport->signatures[0]->errors),
        );

        self::saveArtefact(\sprintf('mobile-id-%s.asice', $code), $bytes);
    }

    /**
     * Keep the produced container when ALLKIRI_ARTEFACTS points somewhere, so
     * it can be opened in DigiDoc4 for the manual checklist.
     */
    private static function saveArtefact(string $name, string $bytes): void
    {
        $directory = getenv('ALLKIRI_ARTEFACTS');
        if (!\is_string($directory) || $directory === '' || !is_dir($directory)) {
            return;
        }
        file_put_contents(rtrim($directory, '/\\') . \DIRECTORY_SEPARATOR . $name, $bytes);
    }
}
