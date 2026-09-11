<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Crypto;

use Allkiri\Crypto\RandomNonceGenerator;
use Allkiri\Tests\Support\Crypto\FixedNonceGenerator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(RandomNonceGenerator::class)]
final class NonceGeneratorTest extends TestCase
{
    public function testRandomNoncesHaveTheRequestedLengthAndDiffer(): void
    {
        $generator = new RandomNonceGenerator();

        self::assertSame(32, \strlen($generator->generate(32)));
        self::assertNotSame($generator->generate(16), $generator->generate(16));
    }

    public function testFixedNoncesAreDeterministicPerCallSequence(): void
    {
        $a = new FixedNonceGenerator('seed');
        $b = new FixedNonceGenerator('seed');

        self::assertSame($a->generate(8), $b->generate(8));
        self::assertNotSame($a->generate(8), $a->generate(8), 'consecutive nonces differ');
        self::assertSame(100, \strlen((new FixedNonceGenerator())->generate(100)));
    }
}
