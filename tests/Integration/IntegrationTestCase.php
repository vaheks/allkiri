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
}
