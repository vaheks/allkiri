<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit;

use Allkiri\Crypto\PrivateKey;
use Allkiri\Exception\InvalidArgumentException;
use Allkiri\MobileId\MobileIdConfiguration;
use Allkiri\Signing\LocalKeySigner;
use Allkiri\SmartId\DeviceLink;
use Allkiri\SmartId\DeviceLinkSessionResponse;
use Allkiri\SmartId\SmartIdConfiguration;
use Allkiri\SmartId\SmartIdSession;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Secrets stay out of stack traces: a password, key material, a Smart-ID
 * session secret or a relying-party identifier shows up as a
 * SensitiveParameterValue wherever an exception passes through the function
 * that was given it.
 */
#[CoversNothing]
final class SensitiveParameterTest extends TestCase
{
    /**
     * @return iterable<string, array{class-string, string, string}>
     */
    public static function secrets(): iterable
    {
        yield 'a private key' => [PrivateKey::class, '__construct', 'key'];
        yield 'PEM key material' => [PrivateKey::class, 'fromPem', 'pem'];
        yield 'a PEM password' => [PrivateKey::class, 'fromPem', 'password'];
        yield 'PKCS#12 key material' => [PrivateKey::class, 'fromPkcs12', 'pkcs12'];
        yield 'a PKCS#12 password' => [PrivateKey::class, 'fromPkcs12', 'password'];
        yield 'PKCS#12 key material for a local signer' => [LocalKeySigner::class, 'fromPkcs12', 'pkcs12'];
        yield 'a PKCS#12 password for a local signer' => [LocalKeySigner::class, 'fromPkcs12', 'password'];
        yield 'the session secret a link is built with' => [DeviceLink::class, 'url', 'sessionSecret'];
        yield 'the session secret an authentication code is built with' => [DeviceLink::class, 'authenticationCode', 'sessionSecret'];
        yield 'the session secret the service returns' => [DeviceLinkSessionResponse::class, '__construct', 'sessionSecret'];
        yield 'the answer carrying the session secret' => [DeviceLinkSessionResponse::class, 'fromArray', 'body'];
        yield 'the session secret a session keeps' => [SmartIdSession::class, '__construct', 'sessionSecret'];
        yield 'a stored session carrying its secret' => [SmartIdSession::class, 'fromArray', 'data'];
        yield 'the Mobile-ID relying party identifier' => [MobileIdConfiguration::class, '__construct', 'relyingPartyUuid'];
        yield 'the Mobile-ID relying party identifier in production' => [MobileIdConfiguration::class, 'production', 'relyingPartyUuid'];
        yield 'the Smart-ID relying party identifier' => [SmartIdConfiguration::class, '__construct', 'relyingPartyUuid'];
        yield 'the Smart-ID relying party identifier in production' => [SmartIdConfiguration::class, 'production', 'relyingPartyUuid'];
    }

    /**
     * @param class-string $class
     */
    #[DataProvider('secrets')]
    public function testTheSecretIsMarkedSensitive(string $class, string $method, string $parameter): void
    {
        $found = null;
        foreach ((new \ReflectionMethod($class, $method))->getParameters() as $candidate) {
            if ($candidate->getName() === $parameter) {
                $found = $candidate;
            }
        }

        self::assertNotNull($found, \sprintf('%s::%s() has no parameter $%s', $class, $method, $parameter));
        self::assertCount(1, $found->getAttributes(\SensitiveParameter::class));
    }

    public function testASessionSecretDoesNotReachAStackTrace(): void
    {
        // Production configurations usually leave arguments out of traces
        // altogether, which would make this pass for the wrong reason.
        $previous = ini_set('zend.exception_ignore_args', '0');
        $link = new DeviceLink('smart-id-demo', 'https://smart-id.test/dl', DeviceLink::TYPE_QR, DeviceLink::SESSION_AUTHENTICATION, 'token', 'REVNTw==', 'W10=', 'Y2hhbGxlbmdl');

        try {
            $link->authenticationCode('not a secret %%%', 'https://smart-id.test/dl?x');
            self::fail('A session secret that is not base64 was accepted');
        } catch (InvalidArgumentException $exception) {
            $arguments = $exception->getTrace()[0]['args'] ?? [];
            self::assertInstanceOf(\SensitiveParameterValue::class, $arguments[0] ?? null);
            self::assertStringNotContainsString('not a secret', $exception->getTraceAsString());
        } finally {
            if (\is_string($previous)) {
                ini_set('zend.exception_ignore_args', $previous);
            }
        }
    }
}
