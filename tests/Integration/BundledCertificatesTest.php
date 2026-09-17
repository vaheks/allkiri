<?php

declare(strict_types=1);

namespace Allkiri\Tests\Integration;

use Allkiri\Crypto\Certificate;
use Allkiri\Resources;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * The certificates shipped in resources/trust, checked against today's date.
 *
 * Nothing in the library looks at their validity: a trusted list is accepted
 * when its signer is byte for byte one of them, so an expiring certificate
 * gives no warning of its own. This does, well before the date. It lives
 * with the integration tests because its outcome depends on the day it runs,
 * which the unit suite must not.
 */
final class BundledCertificatesTest extends IntegrationTestCase
{
    /** How long before its expiry a bundled certificate fails the nightly. */
    private const WARN_DAYS = 90;

    /** Where a replacement comes from, by directory under resources/trust. */
    private const REPLACEMENTS = [
        'eu' => 'the Official Journal, as the whole set; resources/trust/eu/README.md describes the refresh',
        'test' => 'RIA, at https://open-eid.github.io/test-TL/trusted-test-tsl.crt',
        'test/zetes' => 'Zetes, at https://crt-test.eidpki.ee/ (docs/specs.md names both files)',
    ];

    #[DataProvider('bundledCertificates')]
    public function testABundledCertificateIsNotAboutToExpire(string $relative): void
    {
        $pem = Resources::read($relative);
        self::assertSame(1, substr_count($pem, '-----BEGIN CERTIFICATE-----'), $relative . ' should hold exactly one certificate');
        $certificate = Certificate::fromPem($pem);

        $deadline = (new \DateTimeImmutable())->modify(\sprintf('+%d days', self::WARN_DAYS));

        self::assertGreaterThan($deadline, $certificate->notAfter(), \sprintf(
            'resources/%s (%s) expires on %s, within %d days. Its replacement comes from %s.',
            $relative,
            $certificate->subjectDn(),
            $certificate->notAfter()->format('Y-m-d'),
            self::WARN_DAYS,
            self::REPLACEMENTS[substr(\dirname($relative), \strlen('trust/'))] ?? 'wherever it was taken from; add that source to this test',
        ));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function bundledCertificates(): iterable
    {
        $root = Resources::path('trust');
        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS));
        $found = [];
        foreach ($files as $file) {
            if ($file instanceof \SplFileInfo && $file->isFile() && $file->getExtension() === 'pem') {
                $relative = 'trust/' . str_replace('\\', '/', substr($file->getPathname(), \strlen($root) + 1));
                $found[$relative] = [$relative];
            }
        }
        ksort($found);

        return $found;
    }
}
