<?php

declare(strict_types=1);

namespace Allkiri\Tests\Integration;

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
}
