<?php

declare(strict_types=1);

/**
 * The one place this demo reads its environment.
 *
 * There are two modes and nothing in between. `demo` talks to SK's free test
 * services with the credentials SK publishes, and every signature it makes is
 * worthless by design. `live` talks to the real services with your own
 * credentials, and every signature it makes is a real signature by a real
 * person, on a service that bills you per timestamp.
 *
 * Because those two things look identical on screen, the mode is one explicit
 * word rather than a boolean, live mode refuses to start unless everything it
 * needs is present, and the page says which mode it is in.
 *
 * The library itself reads no environment variables at all. This file exists
 * because an application has to decide these things, and showing how is the
 * demo's job.
 */

namespace Allkiri\Demo;

use Allkiri\Config\Environment;
use Allkiri\MobileId\MobileIdConfiguration;
use Allkiri\SmartId\SmartIdConfiguration;
use Allkiri\WebEid\WebEidConfiguration;

final class Config
{
    public const MODE_DEMO = 'demo';
    public const MODE_LIVE = 'live';

    /** The relying-party values live mode needs, and demo mode must not carry. */
    private const RELYING_PARTY_VARIABLES = [
        'ALLKIRI_MID_RP_UUID',
        'ALLKIRI_MID_RP_NAME',
        'ALLKIRI_SMARTID_RP_UUID',
        'ALLKIRI_SMARTID_RP_NAME',
    ];

    private function __construct(
        public readonly string $mode,
        public readonly Environment $environment,
        public readonly MobileIdConfiguration $mobileId,
        public readonly SmartIdConfiguration $smartId,
        public readonly WebEidConfiguration $webEid,
        public readonly ?string $caBundle,
    ) {}

    public static function fromEnvironment(): self
    {
        self::loadDotEnv(__DIR__ . '/../../.env');

        $mode = strtolower(self::env('ALLKIRI_MODE', self::MODE_DEMO));
        if ($mode !== self::MODE_DEMO && $mode !== self::MODE_LIVE) {
            throw new \RuntimeException(\sprintf(
                'ALLKIRI_MODE is "%s"; it must be exactly "%s" or "%s"',
                $mode,
                self::MODE_DEMO,
                self::MODE_LIVE,
            ));
        }

        $bundle = self::env('ALLKIRI_CA_BUNDLE', '');

        return $mode === self::MODE_LIVE ? self::live($bundle) : self::demo($bundle);
    }

    public function isLive(): bool
    {
        return $this->mode === self::MODE_LIVE;
    }

    /**
     * What the page shows in its banner. In live mode this is the name the
     * person will see on their phone, which is worth checking before signing.
     */
    public function relyingPartyName(): string
    {
        return $this->mobileId->relyingPartyName;
    }

    /**
     * What to call this service in the text shown on someone's phone.
     *
     * "the allkiri demo" is honest in demo mode and a lie in live mode, where a
     * real person is being asked to authorise something and the wording is the
     * only thing telling them what.
     */
    public function serviceName(): string
    {
        return $this->isLive() ? $this->relyingPartyName() : 'the allkiri demo';
    }

    // --- the two modes ------------------------------------------------------

    private static function demo(string $bundle): self
    {
        // Demo credentials are hardcoded on purpose: SK publishes them, every
        // reader of this file already has them, and there is nothing to
        // protect. What matters is that they cannot be confused with real ones.
        $configured = array_values(array_filter(
            self::RELYING_PARTY_VARIABLES,
            static fn(string $name): bool => self::env($name, '') !== '',
        ));
        if ($configured !== []) {
            throw new \RuntimeException(\sprintf(
                "ALLKIRI_MODE is \"demo\" but these are set: %s.\n"
                . "Demo mode uses the credentials SK publishes, so your own would not be used and the signatures would not be real.\n"
                . 'Set ALLKIRI_MODE=live to use them, or remove them to run against the test services.',
                implode(', ', $configured),
            ));
        }

        return new self(
            self::MODE_DEMO,
            Environment::demo(),
            MobileIdConfiguration::demo('allkiri demo'),
            SmartIdConfiguration::demo(),
            // Whatever the browser reports as location.origin, exactly. The
            // card signs it, and a mismatch verifies nothing.
            WebEidConfiguration::forOrigin(self::env('ALLKIRI_ORIGIN', 'https://localhost:8443')),
            $bundle === '' ? null : $bundle,
        );
    }

    private static function live(string $bundle): self
    {
        $required = [...self::RELYING_PARTY_VARIABLES, 'ALLKIRI_ORIGIN'];
        $missing = array_values(array_filter(
            $required,
            static fn(string $name): bool => self::env($name, '') === '',
        ));
        // All of them at once. Finding out one variable at a time, each time
        // through a browser and an eID service, is how an afternoon disappears.
        if ($missing !== []) {
            throw new \RuntimeException(\sprintf(
                "ALLKIRI_MODE is \"live\" but these are missing: %s.\n"
                . 'See .env.example. Live mode will not fall back to the demo services, because a signature made against them looks valid and is worth nothing.',
                implode(', ', $missing),
            ));
        }

        $midUuid = self::env('ALLKIRI_MID_RP_UUID', '');
        $midName = self::env('ALLKIRI_MID_RP_NAME', '');
        $sidUuid = self::env('ALLKIRI_SMARTID_RP_UUID', '');
        $sidName = self::env('ALLKIRI_SMARTID_RP_NAME', '');

        // The published demo identifiers against the live services would fail
        // anyway, but they would fail as an authorisation error somewhere deep
        // in a signing flow rather than here, where the cause is obvious.
        self::refuseDemoCredentials('Mobile-ID', $midUuid, $midName, MobileIdConfiguration::DEMO_RELYING_PARTY_UUID);
        self::refuseDemoCredentials('Smart-ID', $sidUuid, $sidName, SmartIdConfiguration::DEMO_RELYING_PARTY_UUID);

        return new self(
            self::MODE_LIVE,
            Environment::production(),
            // No display text unless one is given. Mobile-ID shows the relying
            // party's name regardless, and a wrong sentence above it is worse
            // than none. It is also checked against what GSM-7 can carry, so a
            // name with "õ" in it would refuse to start rather than sign.
            MobileIdConfiguration::production($midUuid, $midName, self::env('ALLKIRI_MID_DISPLAY_TEXT', '')),
            SmartIdConfiguration::production($sidUuid, $sidName),
            WebEidConfiguration::forOrigin(self::env('ALLKIRI_ORIGIN', '')),
            $bundle === '' ? null : $bundle,
        );
    }

    private static function refuseDemoCredentials(string $service, string $uuid, string $name, string $demoUuid): void
    {
        if ($uuid === $demoUuid || strtoupper($name) === 'DEMO') {
            throw new \RuntimeException(\sprintf(
                'ALLKIRI_MODE is "live" but the %s credentials are the ones SK publishes for the demo environment. Use the identifier and name from your own contract.',
                $service,
            ));
        }
    }

    // --- reading the environment --------------------------------------------

    private static function env(string $name, string $fallback): string
    {
        $value = getenv($name);

        return \is_string($value) && $value !== '' ? trim($value) : $fallback;
    }

    /**
     * Enough of a .env reader for this demo: KEY=VALUE a line, # comments,
     * optional surrounding quotes. Anything already in the real environment
     * wins, so an exported variable is never quietly overridden by a file.
     *
     * A real application uses its framework's loader. The test suite has its
     * own copy of this in tests/bootstrap.php, because neither half should have
     * to require the other.
     */
    private static function loadDotEnv(string $path): void
    {
        if (!is_file($path)) {
            return;
        }
        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            return;
        }
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            $separator = strpos($line, '=');
            if ($separator === false) {
                continue;
            }
            $name = trim(substr($line, 0, $separator));
            $value = trim(substr($line, $separator + 1));
            if (\strlen($value) >= 2 && ($value[0] === '"' || $value[0] === "'") && $value[-1] === $value[0]) {
                $value = substr($value, 1, -1);
            }
            if ($name !== '' && getenv($name) === false) {
                putenv($name . '=' . $value);
            }
        }
    }
}
