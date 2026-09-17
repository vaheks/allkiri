<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\SmartId;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\SmartId\SmartIdCallback;
use Allkiri\Tests\Support\Crypto\FixedNonceGenerator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(SmartIdCallback::class)]
final class SmartIdCallbackTest extends TestCase
{
    public function testAnInitialUrlGetsAnUnguessableValue(): void
    {
        $url = SmartIdCallback::initialUrl('https://rp.example.test/smart-id/callback');

        self::assertMatchesRegularExpression('#^https://rp\.example\.test/smart-id/callback\?value=[A-Za-z0-9_-]{43}$#', $url);
        self::assertNotSame($url, SmartIdCallback::initialUrl('https://rp.example.test/smart-id/callback'), 'no two sessions share one');
    }

    public function testTheValueIsAddedToAQueryAlreadyThere(): void
    {
        $url = SmartIdCallback::initialUrl('https://rp.example.test/back?lang=et', new FixedNonceGenerator());

        self::assertStringStartsWith('https://rp.example.test/back?lang=et&value=', $url);
        self::assertSame(['lang', 'value'], array_keys(SmartIdCallback::fromUrl($url)->parameters));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function unusableBases(): iterable
    {
        yield 'plain HTTP to another host' => ['http://rp.example.test/back', 'must be an https:// URL'];
        yield 'a fragment the app would drop' => ['https://rp.example.test/back#done', 'must not have a fragment'];
        yield 'a value of its own' => ['https://rp.example.test/back?value=fixed', 'already has a "value" parameter'];
        yield 'a pipe, which separates the signed fields' => ['https://rp.example.test/back?a=|', 'must not be empty or contain "|"'];
    }

    #[DataProvider('unusableBases')]
    public function testAnUnusableBaseIsRefused(string $base, string $message): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        SmartIdCallback::initialUrl($base);
    }

    public function testThisMachineMayBePlainHttp(): void
    {
        self::assertStringStartsWith('http://localhost:8080/back?value=', SmartIdCallback::initialUrl('http://localhost:8080/back'));
    }

    public function testTheAppsParametersAreRead(): void
    {
        $callback = SmartIdCallback::fromUrl('https://rp.example.com/callback-url?value=RrKjjT4aggzu27YBddX1bQ&sessionSecretDigest=U4CKK13H1XFiyBofev9asqrzIrY5_Gszi_nL_zDKkBc&userChallengeVerifier=XtPfaGa8JnGtYrJjboooUf0KfY9sMEHrWFpSQrsUv9c');

        self::assertSame('RrKjjT4aggzu27YBddX1bQ', $callback->parameters[SmartIdCallback::VALUE]);
        self::assertSame('U4CKK13H1XFiyBofev9asqrzIrY5_Gszi_nL_zDKkBc', $callback->sessionSecretDigest());
        self::assertSame('XtPfaGa8JnGtYrJjboooUf0KfY9sMEHrWFpSQrsUv9c', $callback->userChallengeVerifier());
    }

    public function testASigningCallbackHasNoVerifier(): void
    {
        $callback = SmartIdCallback::fromUrl('https://rp.example.com/callback-url?value=RrKjjT4aggzu27YBddX1bQ&sessionSecretDigest=U4CKK13H1XFiyBofev9asqrzIrY5_Gszi_nL_zDKkBc');

        self::assertNull($callback->userChallengeVerifier());
    }

    /**
     * `$_GET` turns `a[]=1` into an array, which is never one of the app's
     * parameters and must not stand in for one.
     */
    public function testOnlyPlainValuesAreTakenFromAQuery(): void
    {
        $callback = SmartIdCallback::fromQuery(['value' => ['x'], 'sessionSecretDigest' => 'abc', 7 => 'seven']);

        self::assertSame(['sessionSecretDigest' => 'abc', '7' => 'seven'], $callback->parameters);
        self::assertSame([], SmartIdCallback::fromUrl('https://rp.example.test/back')->parameters);
    }
}
