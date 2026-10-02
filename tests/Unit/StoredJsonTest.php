<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit;

use Allkiri\Auth\AuthenticatedIdentity;
use Allkiri\Container\AsicContainer;
use Allkiri\Container\AsicWriter;
use Allkiri\Container\DataFile;
use Allkiri\MobileId\MobileIdSession;
use Allkiri\MobileId\MobileIdSigningSession;
use Allkiri\Signing\DataToBeSigned;
use Allkiri\Signing\LocalKeySigner;
use Allkiri\SmartId\SmartIdSession;
use Allkiri\SmartId\SmartIdSigningSession;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Tests\Support\SigningFixture;
use Allkiri\Validation\ContainerValidator;
use Allkiri\Validation\SignatureValidator;
use Allkiri\WebEid\WebEidChallenge;
use Allkiri\WebEid\WebEidSigningSession;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * What an application stored with an earlier release still reads.
 *
 * The files in tests/fixtures/stored were written by 0.8.0-alpha.1, by the
 * generate.php beside them, and are never rewritten: a round trip through
 * today's code would only prove that today agrees with itself. docs/releasing.md
 * promises that a minor release reads what an earlier one wrote, and this is
 * where that promise is kept.
 */
#[CoversNothing]
final class StoredJsonTest extends TestCase
{
    private const STORED = __DIR__ . '/../fixtures/stored/';

    /**
     * @return iterable<string, array{string, \Closure(string): object, string}>
     */
    public static function restorable(): iterable
    {
        yield 'a prepared signature' => ['data-to-be-signed', DataToBeSigned::fromJson(...), 'signatureId'];
        yield 'a Web eID challenge' => ['web-eid-challenge', WebEidChallenge::fromJson(...), 'nonce'];
        yield 'a Web eID signing session' => ['web-eid-signing-session', WebEidSigningSession::fromJson(...), 'dataToBeSigned'];
        yield 'a Mobile-ID session' => ['mobile-id-session', MobileIdSession::fromJson(...), 'sessionId'];
        yield 'a Mobile-ID signing session' => ['mobile-id-signing-session', MobileIdSigningSession::fromJson(...), 'session'];
        yield 'a Smart-ID session' => ['smart-id-session', SmartIdSession::fromJson(...), 'sessionId'];
        yield 'a Smart-ID signing session' => ['smart-id-signing-session', SmartIdSigningSession::fromJson(...), 'session'];
    }

    /**
     * @param \Closure(string): object $restore
     */
    #[DataProvider('restorable')]
    public function testWhatTheLastReleaseStoredIsRestored(string $file, \Closure $restore, string $field): void
    {
        $json = self::read($file);
        $stored = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($stored);

        $restored = $restore($json);

        // Restored, and written back with what it was restored from.
        $again = json_decode((string) json_encode($restored), true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($again);
        self::assertSame($stored[$field], $again[$field], $file . ': ' . $field);
    }

    /**
     * An identity and a report are written for others to read, not read back
     * by the library, so what is kept is their shape: every key the last
     * release wrote is still written, with the same meaning. A key may be
     * added.
     */
    public function testAnIdentityStillCarriesEveryKeyItDid(): void
    {
        $stored = self::decode('authenticated-identity');
        $today = json_decode((string) json_encode(AuthenticatedIdentity::fromCertificate(TestPki::signerRsaPerson()->certificate)), true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($today);

        foreach ($stored as $key => $value) {
            self::assertArrayHasKey($key, $today, 'the identity no longer writes ' . $key);
            self::assertSame($value, $today[$key], $key);
        }
    }

    public function testAReportStillCarriesEveryKeyItDid(): void
    {
        $fixture = new SigningFixture();
        $signed = $fixture->signingService->signWith(AsicContainer::create(DataFile::fromString('leping.txt', "Tere, allkiri!\n")), LocalKeySigner::fromKeyPair(TestPki::signerEc256()));
        $report = (new ContainerValidator(new SignatureValidator($fixture->trustStore), $fixture->clock))->validate((new AsicWriter())->write($signed->container), 'leping.asice');
        $today = json_decode((string) json_encode($report), true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($today);

        self::assertSame([], self::missingKeys(self::decode('validation-report'), $today));
        self::assertSame(1, $today['version'] ?? null);
    }

    /**
     * Every key path in the stored JSON that today's JSON does not have. Lists
     * are compared by their first entry.
     *
     * @param array<mixed> $stored
     * @param array<mixed> $today
     *
     * @return list<string>
     */
    private static function missingKeys(array $stored, array $today, string $path = ''): array
    {
        $missing = [];
        foreach ($stored as $key => $value) {
            $here = $path . '/' . $key;
            if (array_is_list($stored)) {
                $key = 0;
            }
            if (!\array_key_exists($key, $today)) {
                $missing[] = $here;
                continue;
            }
            if (\is_array($value) && \is_array($today[$key])) {
                array_push($missing, ...self::missingKeys($value, $today[$key], $here));
            }
            if (array_is_list($stored)) {
                break;
            }
        }

        return $missing;
    }

    /**
     * @return array<mixed>
     */
    private static function decode(string $file): array
    {
        $decoded = json_decode(self::read($file), true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        return $decoded;
    }

    private static function read(string $file): string
    {
        return (string) file_get_contents(self::STORED . $file . '.json');
    }
}
