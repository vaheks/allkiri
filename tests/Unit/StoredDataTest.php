<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit;

use Allkiri\Container\AsicContainer;
use Allkiri\Container\DataFile;
use Allkiri\Crypto\CertificateException;
use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Exception\SessionDataException;
use Allkiri\MobileId\MobileIdIdentity;
use Allkiri\MobileId\MobileIdSession;
use Allkiri\MobileId\MobileIdSigningSession;
use Allkiri\Signing\DataToBeSigned;
use Allkiri\SmartId\CertificateLevel;
use Allkiri\SmartId\Interaction;
use Allkiri\SmartId\Interactions;
use Allkiri\SmartId\SmartIdSession;
use Allkiri\SmartId\SmartIdSigningSession;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Tests\Support\SigningFixture;
use Allkiri\WebEid\CardAlgorithm;
use Allkiri\WebEid\WebEidChallenge;
use Allkiri\WebEid\WebEidException;
use Allkiri\WebEid\WebEidSigningSession;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Everything kept between requests is read back by one reader, which refuses
 * malformed data the same way for every kind of session and keeps the stored
 * data out of stack traces.
 */
#[CoversNothing]
final class StoredDataTest extends TestCase
{
    private const SECRET = 'c2VjcmV0IHRoYXQgbXVzdCBub3QgbGVhaw==';

    /** @var array<string, array<mixed>>|null */
    private static ?array $stored = null;

    /**
     * What each kind of stored object writes, by the name its messages use.
     *
     * @return array<string, array<mixed>>
     */
    private static function stored(): array
    {
        if (self::$stored !== null) {
            return self::$stored;
        }

        $prepared = (new SigningFixture())->signingService->prepare(AsicContainer::create(DataFile::fromString('a.txt', 'x')), TestPki::signerEc256()->certificate);
        $identity = new MobileIdIdentity('+37200000766', '60001019906');
        $interactions = Interactions::of(Interaction::displayTextAndPin('Log in'));
        $smartIdSession = static fn(string $type): SmartIdSession => new SmartIdSession(
            'session-id',
            $type,
            'challenge bytes',
            $interactions,
            verificationCode: '1234',
            sessionToken: 'token',
            sessionSecret: self::SECRET,
            deviceLinkBase: 'https://smart-id.test/dl',
            startedAt: new \DateTimeImmutable('2026-03-01T10:00:00Z'),
            certificateLevel: CertificateLevel::Qualified,
        );

        return self::$stored = [
            'DataToBeSigned' => $prepared->jsonSerialize(),
            'Mobile-ID session' => (new MobileIdSession('session-id', MobileIdSession::TYPE_AUTHENTICATION, '1234', $identity, 'challenge bytes'))->jsonSerialize(),
            'Mobile-ID signing session' => (new MobileIdSigningSession(new MobileIdSession('session-id', MobileIdSession::TYPE_SIGNATURE, '1234', $identity), $prepared))->jsonSerialize(),
            'Smart-ID session' => $smartIdSession(SmartIdSession::TYPE_AUTHENTICATION)->jsonSerialize(),
            'Smart-ID signing session' => (new SmartIdSigningSession($smartIdSession(SmartIdSession::TYPE_SIGNATURE), $prepared))->jsonSerialize(),
            'Web eID challenge' => (new WebEidChallenge(str_repeat('A', 44), new \DateTimeImmutable('2026-03-01T10:00:00Z'), new \DateTimeImmutable('2026-03-01T10:05:00Z')))->jsonSerialize(),
            'Web eID signing session' => (new WebEidSigningSession($prepared, new CardAlgorithm(CardAlgorithm::CRYPTO_ECC, 'SHA-256', CardAlgorithm::PADDING_NONE)))->jsonSerialize(),
        ];
    }

    /**
     * @return array<string, \Closure(string): \JsonSerializable>
     */
    private static function restorers(): array
    {
        return [
            'DataToBeSigned' => DataToBeSigned::fromJson(...),
            'Mobile-ID session' => MobileIdSession::fromJson(...),
            'Mobile-ID signing session' => MobileIdSigningSession::fromJson(...),
            'Smart-ID session' => SmartIdSession::fromJson(...),
            'Smart-ID signing session' => SmartIdSigningSession::fromJson(...),
            'Web eID challenge' => WebEidChallenge::fromJson(...),
            'Web eID signing session' => WebEidSigningSession::fromJson(...),
        ];
    }

    public function testWhatWasStoredIsRestored(): void
    {
        foreach (self::restorers() as $label => $restore) {
            $stored = self::stored()[$label];
            $json = json_encode($stored, JSON_THROW_ON_ERROR);

            self::assertSame($json, json_encode($restore($json), JSON_THROW_ON_ERROR), $label);
        }
    }

    /**
     * @return iterable<string, array{string, \Closure(array<mixed>): (array<mixed>|string), string}>
     */
    public static function malformed(): iterable
    {
        $set = static fn(string $key, mixed $value): \Closure => static fn(array $data): array => [$key => $value] + $data;
        $without = static fn(string $key): \Closure => static function (array $data) use ($key): array {
            unset($data[$key]);

            return $data;
        };

        foreach (['DataToBeSigned', 'Mobile-ID session', 'Mobile-ID signing session', 'Smart-ID session', 'Smart-ID signing session', 'Web eID challenge', 'Web eID signing session'] as $label) {
            yield $label . ': not JSON' => [$label, static fn(array $data): string => '{"version": 1,', $label . ' JSON is not an object'];
            yield $label . ': a version it does not read' => [$label, $set('version', 99), 'Unsupported ' . $label . ' version 99'];
            yield $label . ': no version' => [$label, $without('version'), 'Unsupported ' . $label . ' version null'];
        }

        yield 'a prepared signature missing a field' => ['DataToBeSigned', $without('signatureId'), 'DataToBeSigned is missing "signatureId"'];
        yield 'a number where text belongs' => ['DataToBeSigned', $set('signatureFileName', 5), 'DataToBeSigned field "signatureFileName" must be a non-empty string'];
        yield 'a digest that is not base64' => ['DataToBeSigned', $set('digest', '%%%'), 'DataToBeSigned field "digest" is not base64'];
        yield 'an unknown level' => ['DataToBeSigned', $set('level', 'XAdES_BASELINE_Z'), 'DataToBeSigned field "level" has an unknown value'];
        yield 'an unknown algorithm' => ['DataToBeSigned', $set('algorithm', 'https://algorithm.test/none'), 'DataToBeSigned field "algorithm" has an unknown value'];
        yield 'a relative date' => ['DataToBeSigned', $set('createdAt', 'now'), 'DataToBeSigned field "createdAt" is not a date'];
        yield 'a Mobile-ID challenge that is not base64' => ['Mobile-ID session', $set('challenge', '%%%'), 'Mobile-ID session field "challenge" is not base64'];
        yield 'a Mobile-ID session with no challenge' => ['Mobile-ID session', $without('challenge'), 'Mobile-ID session is missing "challenge"'];
        yield 'a signing session with no session' => ['Mobile-ID signing session', $without('session'), 'Mobile-ID signing session is missing "session"'];
        yield 'a session that is not an object' => ['Mobile-ID signing session', $set('session', 'session'), 'Mobile-ID signing session field "session" is not an object'];
        yield 'a nested session missing a field' => [
            'Mobile-ID signing session',
            static function (array $data): array {
                $session = \is_array($data['session'] ?? null) ? $data['session'] : [];
                unset($session['sessionId']);

                return ['session' => $session] + $data;
            },
            'Mobile-ID session is missing "sessionId"',
        ];
        yield 'an unknown certificate level' => ['Smart-ID session', $set('certificateLevel', 'SUPREME'), 'Smart-ID session field "certificateLevel" has an unknown value'];
        yield 'a number where optional text belongs' => ['Smart-ID session', $set('documentNumber', 5), 'Smart-ID session field "documentNumber" must be a string'];
        yield 'a start time that is not a date' => ['Smart-ID session', $set('startedAt', 'yesterday'), 'Smart-ID session field "startedAt" is not a date'];
        yield 'a signing session with no data to be signed' => ['Smart-ID signing session', $without('dataToBeSigned'), 'Smart-ID signing session is missing "dataToBeSigned"'];
        yield 'an issue time that is not a date' => ['Web eID challenge', $set('issuedAt', 'garbage'), 'Web eID challenge field "issuedAt" is not a date'];
        yield 'a challenge with no nonce' => ['Web eID challenge', $without('nonce'), 'Web eID challenge is missing "nonce"'];
        yield 'a card signing session with no algorithm' => ['Web eID signing session', $without('algorithm'), 'Web eID signing session is missing "algorithm"'];
    }

    /**
     * @param \Closure(array<mixed>): (array<mixed>|string) $mutate
     */
    #[DataProvider('malformed')]
    public function testMalformedStoredDataIsRefused(string $label, \Closure $mutate, string $message): void
    {
        $mutated = $mutate(self::stored()[$label]);
        $json = \is_string($mutated) ? $mutated : json_encode($mutated, JSON_THROW_ON_ERROR);

        try {
            self::restorers()[$label]($json);
            self::fail(\sprintf('A malformed %s was restored', $label));
        } catch (SessionDataException $exception) {
            self::assertStringContainsString($message, $exception->getMessage());
            self::assertStringNotContainsString(self::SECRET, $exception->getMessage());
        }
    }

    /**
     * @return iterable<string, array{string, \Closure(array<mixed>): array<mixed>, class-string<\Throwable>}>
     */
    public static function refusedByTheObject(): iterable
    {
        $set = static fn(string $key, mixed $value): \Closure => static fn(array $data): array => [$key => $value] + $data;

        yield 'a certificate that is not one' => ['DataToBeSigned', $set('signerCertificate', 'AAAA'), CertificateException::class];
        yield 'a phone number in no known form' => ['Mobile-ID session', $set('phoneNumber', '123'), InvalidArgumentException::class];
        yield 'a challenge that expires before it was issued' => ['Web eID challenge', $set('expiresAt', '2026-03-01T09:00:00+00:00'), InvalidArgumentException::class];
        yield 'a session started for an account and a person' => [
            'Smart-ID session',
            static fn(array $data): array => ['documentNumber' => 'PNOEE-40504040001-MOCK-Q', 'semanticsIdentifier' => 'PNOEE-40504040001'] + $data,
            InvalidArgumentException::class,
        ];
        yield 'an interaction of a type Smart-ID does not have' => ['Smart-ID session', $set('interactions', base64_encode('[{"type":"telepathy","displayText60":"Log in"}]')), \ValueError::class];
        yield 'a nested session of the wrong type' => [
            'Mobile-ID signing session',
            static function (array $data): array {
                $session = \is_array($data['session'] ?? null) ? $data['session'] : [];

                return ['session' => ['type' => MobileIdSession::TYPE_AUTHENTICATION] + $session] + $data;
            },
            InvalidArgumentException::class,
        ];
        yield 'a card algorithm with nothing in it' => ['Web eID signing session', $set('algorithm', []), WebEidException::class];
    }

    /**
     * What the reader accepts but the object refuses, and what PHP itself
     * throws, still arrives as a SessionDataException, with the original kept.
     *
     * @param \Closure(array<mixed>): array<mixed> $mutate
     * @param class-string<\Throwable>             $previous
     */
    #[DataProvider('refusedByTheObject')]
    public function testWhatTheObjectRefusesIsWrapped(string $label, \Closure $mutate, string $previous): void
    {
        try {
            self::restorers()[$label](json_encode($mutate(self::stored()[$label]), JSON_THROW_ON_ERROR));
            self::fail(\sprintf('A malformed %s was restored', $label));
        } catch (SessionDataException $exception) {
            self::assertStringContainsString($label, $exception->getMessage());
            self::assertInstanceOf($previous, $exception->getPrevious());
        }
    }

    public function testANestedFailureIsNotWrappedTwice(): void
    {
        $stored = self::stored()['Mobile-ID signing session'];
        $session = \is_array($stored['session'] ?? null) ? $stored['session'] : [];
        unset($session['sessionId']);

        try {
            MobileIdSigningSession::fromArray(['session' => $session] + $stored);
            self::fail('A signing session with a malformed session was restored');
        } catch (SessionDataException $exception) {
            self::assertSame('Mobile-ID session is missing "sessionId"', $exception->getMessage());
            self::assertNull($exception->getPrevious());
        }
    }

    public function testAStoredSessionMissingAFieldKeepsItsSecretOutOfTheTrace(): void
    {
        // Production configurations usually leave arguments out of traces
        // altogether, which would make this pass for the wrong reason.
        $previous = ini_set('zend.exception_ignore_args', '0');
        $data = self::stored()['Smart-ID session'];
        unset($data['sessionId']);

        try {
            SmartIdSession::fromArray($data);
            self::fail('A stored session without an identifier was restored');
        } catch (SessionDataException $exception) {
            $frames = array_filter(
                $exception->getTrace(),
                static fn(array $frame): bool => str_starts_with($frame['class'] ?? '', 'Allkiri\\') && !str_starts_with($frame['class'] ?? '', 'Allkiri\\Tests\\'),
            );
            self::assertNotSame([], $frames);
            self::assertFalse(self::carries($frames, self::SECRET), 'the session secret reached a stack trace');
        } finally {
            if (\is_string($previous)) {
                ini_set('zend.exception_ignore_args', $previous);
            }
        }
    }

    /**
     * Whether the needle is anywhere in the value, looking inside arrays and
     * objects the way an error reporter serialising a trace would.
     */
    private static function carries(mixed $value, string $needle, int $depth = 0): bool
    {
        if ($depth > 8 || $value instanceof \SensitiveParameterValue) {
            return false;
        }
        if (\is_string($value)) {
            return str_contains($value, $needle);
        }
        if (\is_object($value)) {
            $value = (array) $value;
        }
        if (\is_array($value)) {
            foreach ($value as $item) {
                if (self::carries($item, $needle, $depth + 1)) {
                    return true;
                }
            }
        }

        return false;
    }
}
