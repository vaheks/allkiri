<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit;

use Allkiri\Allkiri;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Allkiri::class)]
final class AllkiriTest extends TestCase
{
    public function testVersionIsSemver(): void
    {
        self::assertMatchesRegularExpression('/^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/', Allkiri::VERSION);
    }

    public function testUserAgentCarriesVersion(): void
    {
        self::assertStringStartsWith('allkiri/' . Allkiri::VERSION, Allkiri::USER_AGENT);
    }
}
