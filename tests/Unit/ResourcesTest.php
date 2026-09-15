<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit;

use Allkiri\Resources;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class ResourcesTest extends TestCase
{
    public function testABundledResourceIsRead(): void
    {
        self::assertStringContainsString('-----BEGIN CERTIFICATE-----', Resources::read('trust/test/test-tsl-signer.pem'));
    }

    /**
     * Only a wrong name reaches this in an intact package, which makes it a
     * programmer error.
     */
    public function testAResourceThatIsNotBundledIsAProgrammerError(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('There is no bundled resource "no/such.pem"');

        Resources::read('no/such.pem');
    }
}
