<?php

declare(strict_types=1);

namespace Allkiri\Tests\Integration;

use Allkiri\Validation\Siva\SivaClient;
use Allkiri\Validation\Siva\SivaException;
use Allkiri\Validation\Siva\SivaReport;
use PHPUnit\Framework\TestCase;

/**
 * Base class for tests that call the SK, RIA or Zetes demo environments.
 *
 * They only run when ALLKIRI_INTEGRATION=1 (set by the integration workflow
 * and by developers who want them locally); otherwise they are skipped so
 * the default `composer test` stays offline and deterministic.
 */
abstract class IntegrationTestCase extends TestCase
{
    /** How long to wait before asking SiVa again after a challenge. */
    private const SIVA_CHALLENGE_PAUSE_SECONDS = 10;

    protected function setUp(): void
    {
        parent::setUp();

        if (getenv('ALLKIRI_INTEGRATION') !== '1') {
            self::markTestSkipped('Set ALLKIRI_INTEGRATION=1 to run tests against the demo environments.');
        }
    }

    /** Read a demo-environment parameter, falling back to the public DEMO value. */
    protected static function env(string $name, string $default): string
    {
        $value = getenv($name);

        return \is_string($value) && $value !== '' ? $value : $default;
    }

    /**
     * An HTTP client that can reach HTTPS even where PHP has no CA bundle
     * configured: set ALLKIRI_CA_BUNDLE to a PEM file of trusted authorities.
     */
    protected static function http(int $timeoutSeconds = 30): \Allkiri\Http\CurlHttpClient
    {
        $bundle = getenv('ALLKIRI_CA_BUNDLE');

        return new \Allkiri\Http\CurlHttpClient($timeoutSeconds, caBundlePath: \is_string($bundle) && $bundle !== '' ? $bundle : null);
    }

    /**
     * SiVa's verdict, allowing for the bot protection in front of it.
     *
     * RIA put SiVa behind Cloudflare in 2026, and a CI runner is now and then
     * answered with a challenge page. That says nothing about the container, so
     * SiVa is asked once more after a pause, and a second challenge skips the
     * rest of the test instead of failing it. Whatever the test checked before
     * asking SiVa has already passed or failed by then.
     */
    protected static function askSiva(SivaClient $siva, string $container, string $filename): SivaReport
    {
        for ($attempt = 1; ; ++$attempt) {
            try {
                return $siva->validate($container, $filename);
            } catch (SivaException $e) {
                if ($e->reason !== SivaException::REASON_CHALLENGED) {
                    throw $e;
                }
                if ($attempt === 2) {
                    self::markTestSkipped('No verdict from SiVa, challenged twice: ' . $e->getMessage());
                }
            }
            sleep(self::SIVA_CHALLENGE_PAUSE_SECONDS);
        }
    }
}
