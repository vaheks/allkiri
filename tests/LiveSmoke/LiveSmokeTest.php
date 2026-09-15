<?php

declare(strict_types=1);

namespace Allkiri\Tests\LiveSmoke;

use Allkiri\Allkiri;
use Allkiri\Container\AsicContainer;
use Allkiri\Container\AsicWriter;
use Allkiri\Container\DataFile;
use Allkiri\Demo\Config;
use Allkiri\Http\CurlHttpClient;
use Allkiri\MobileId\MobileIdIdentity;
use Allkiri\MobileId\MobileIdPoller;
use Allkiri\Signing\SignatureLevel;
use Allkiri\SmartId\CertificateLevel;
use Allkiri\SmartId\Interaction;
use Allkiri\SmartId\Interactions;
use Allkiri\SmartId\SemanticsIdentifier;
use Allkiri\SmartId\SmartIdPoller;
use Allkiri\Validation\Report\Indication;
use Allkiri\Validation\Siva\SivaClient;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * The production smoke test: one real signature by each remote mean, against
 * the live services, validated by us and by SiVa production.
 *
 * This is the last gate before 1.0, and the only test here that costs money and
 * needs a person. It is deliberately hard to run by accident:
 *
 *   - it lives in its own test suite, so `composer test` and
 *     `composer test:integration` never load it;
 *   - it needs ALLKIRI_LIVE_SMOKE=1, which nothing scheduled sets;
 *   - it needs ALLKIRI_MODE=live with real relying-party credentials;
 *   - it needs a phone number and identity code belonging to whoever is running
 *     it, because a real request goes to a real phone.
 *
 * Run it, then record the result in docs/manual-testing.md:
 *
 *   composer test:live
 *
 * Two Smart-ID interactions are needed rather than one. Signing needs a
 * document number, which identifies one device rather than a person, and asking
 * for it costs an authentication. That is the same shape a real application has,
 * so it is worth exercising.
 *
 * Its settings come through the demo application's `config.php`, not a reader of
 * its own. Live mode's rules are written there: the mode is one explicit word,
 * and live mode refuses to start without every credential it needs. A second
 * copy here could drift from the one a person actually runs, and this test would
 * then prove a rule the demo does not enforce. The price is a test that depends
 * on an example: moving that file or changing `Config::fromEnvironment()` breaks
 * this test, and PHPStan, which analyses both, reports it.
 */
#[CoversNothing]
final class LiveSmokeTest extends TestCase
{
    private Config $config;

    protected function setUp(): void
    {
        parent::setUp();

        if (getenv('ALLKIRI_LIVE_SMOKE') !== '1') {
            self::markTestSkipped(
                'The production smoke test signs for real, with a real phone, on services that bill per timestamp. '
                . 'Set ALLKIRI_LIVE_SMOKE=1 and ALLKIRI_MODE=live to run it. See docs/releasing.md.',
            );
        }

        // The demo application's configuration, so that the mode rules have one
        // implementation and this test exercises it too.
        require_once __DIR__ . '/../../examples/demo-app/config.php';

        $config = Config::fromEnvironment();
        if (!$config->isLive()) {
            self::markTestSkipped('ALLKIRI_LIVE_SMOKE is set but ALLKIRI_MODE is not "live", so this would prove nothing.');
        }
        $this->config = $config;
    }

    public function testARealMobileIdSignatureIsAcceptedEverywhere(): void
    {
        $phone = self::required('ALLKIRI_LIVE_MID_PHONE');
        $code = self::required('ALLKIRI_LIVE_MID_CODE');

        $allkiri = $this->allkiri();
        $signer = $allkiri->mobileIdSigner($this->config->mobileId);
        $container = self::container();

        $signing = $signer->start($container, new MobileIdIdentity($phone, $code));
        fwrite(\STDERR, \sprintf("\nMobile-ID verification code: %s\n", $signing->verificationCode()));

        $status = (new MobileIdPoller($allkiri->mobileIdClient($this->config->mobileId)))->wait($signing->session);
        $result = $signer->complete($container, $signing, $status);

        self::assertSame(SignatureLevel::LT, $result->level);
        $this->assertAcceptedEverywhere((new AsicWriter())->write($result->container), 'live-mobile-id.asice');
    }

    public function testARealSmartIdSignatureIsAcceptedEverywhere(): void
    {
        $code = self::required('ALLKIRI_LIVE_SMARTID_CODE');

        $allkiri = $this->allkiri();
        // QSCD, because that is what a qualified signature requires.
        $configuration = $this->config->smartId->withCertificateLevel(CertificateLevel::Qscd);

        // One authentication, only to learn which device to send the signature
        // request to.
        $authenticator = $allkiri->smartIdAuthenticator($configuration);
        $session = $authenticator->startNotification(
            SemanticsIdentifier::estonian($code),
            self::interactions('allkiri production smoke test'),
        );
        fwrite(\STDERR, \sprintf("\nSmart-ID verification code (authentication): %s\n", (string) $session->verificationCode));

        $status = (new SmartIdPoller($allkiri->smartIdClient($configuration)))->wait($session);
        $authenticator->complete($session, $status);
        $documentNumber = $status->documentNumber;
        self::assertNotNull($documentNumber, 'the service did not say which device answered');

        // Then the signature itself.
        $signer = $allkiri->smartIdSigner($configuration);
        $container = self::container();
        $signing = $signer->startNotification($container, $documentNumber, self::interactions('Sign the allkiri smoke test'));
        fwrite(\STDERR, \sprintf("Smart-ID verification code (signing): %s\n", (string) $signing->verificationCode()));

        $signed = $signer->complete(
            $container,
            $signing,
            (new SmartIdPoller($allkiri->smartIdClient($configuration)))->wait($signing->session),
        );

        self::assertSame(SignatureLevel::LT, $signed->level);
        $this->assertAcceptedEverywhere((new AsicWriter())->write($signed->container), 'live-smart-id.asice');
    }

    /**
     * Both validators, and the artefact kept for DigiDoc4.
     *
     * SiVa production is the opinion that matters here: it is the service the
     * Estonian state runs, on the production trust list, with no test anchors
     * anywhere near it.
     */
    private function assertAcceptedEverywhere(string $bytes, string $name): void
    {
        $report = $this->allkiri()->validator()->validate($bytes, $name);
        $signature = $report->signatures[0];
        self::assertSame(
            Indication::TotalPassed,
            $signature->indication,
            implode('; ', array_map(static fn($f): string => $f->code . ': ' . $f->message, $signature->errors())),
        );
        self::assertSame(SignatureLevel::LT, $signature->format);

        $siva = new SivaClient($this->http(60), (string) $this->config->environment->sivaUrl);
        $sivaReport = $siva->validate($bytes, $name);
        self::assertSame('ASiC-E', $sivaReport->signatureForm);
        self::assertSame(
            'TOTAL-PASSED',
            $sivaReport->signatures[0]->indication,
            implode('; ', $sivaReport->signatures[0]->errors),
        );
        self::assertSame('XAdES_BASELINE_LT', $sivaReport->signatures[0]->signatureFormat);

        self::saveArtefact($name, $bytes);
    }

    private function allkiri(): Allkiri
    {
        return new Allkiri($this->config->environment, $this->http(60));
    }

    private function http(int $timeoutSeconds): CurlHttpClient
    {
        return new CurlHttpClient($timeoutSeconds, caBundlePath: $this->config->caBundle);
    }

    private static function container(): AsicContainer
    {
        return AsicContainer::create(DataFile::fromString(
            'allkiri.txt',
            'allkiri production smoke test, ' . date(DATE_ATOM) . "\n",
        ));
    }

    private static function interactions(string $text): Interactions
    {
        return Interactions::of(
            Interaction::confirmationMessageAndVerificationCodeChoice($text),
            Interaction::confirmationMessage($text),
            Interaction::displayTextAndPin(mb_substr($text, 0, 60)),
        );
    }

    private static function required(string $name): string
    {
        $value = getenv($name);
        if (!\is_string($value) || trim($value) === '') {
            self::markTestSkipped(\sprintf('%s is not set. A live signature needs a real phone number and identity code; see .env.example.', $name));
        }

        return trim($value);
    }

    /**
     * Keep the container: it is the evidence for the release gate, and the thing
     * to open in DigiDoc4's default mode.
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
