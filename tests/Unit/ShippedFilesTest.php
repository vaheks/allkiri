<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit;

use Allkiri\Crypto\Certificate;
use Allkiri\Resources;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Holds the files this repository ships to what it says about them.
 *
 * Two of them are trusted on the strength of a digest written down beside
 * them: a third-party script the demo loads with an `integrity` attribute, and
 * the certificates that decide what production will treat as qualified. A
 * digest that is only in prose is checked by whoever thinks to check it. These
 * tests make a file and the text about it disagree loudly instead.
 */
#[CoversNothing]
final class ShippedFilesTest extends TestCase
{
    private const WEB_EID_JS = 'examples/demo-app/public/vendor/web-eid.js';

    /** Where the same hash is written down, and has to keep matching the file. */
    private const WEB_EID_JS_MENTIONS = [
        'examples/demo-app/views/page.php',
        'docs/browser.md',
        'examples/demo-app/README.md',
    ];

    private static function root(): string
    {
        return \dirname(__DIR__, 2);
    }

    private static function read(string $relative): string
    {
        $path = self::root() . '/' . $relative;
        self::assertFileExists($path);

        return (string) file_get_contents($path);
    }

    // --- the vendored script -------------------------------------------------

    /**
     * The demo loads web-eid.js with an integrity attribute, so a file that
     * does not match the hash is refused by the browser. That is worth nothing
     * if the hash is updated to match whatever the file happens to be, so the
     * file is checked against the hash here, where changing one without the
     * other fails.
     */
    public function testTheVendoredScriptMatchesTheIntegrityHashThePageUses(): void
    {
        $expected = 'sha384-' . base64_encode(hash('sha384', self::read(self::WEB_EID_JS), true));

        foreach (self::WEB_EID_JS_MENTIONS as $file) {
            self::assertStringContainsString(
                $expected,
                self::read($file),
                $file . ' names an integrity hash that is not the one web-eid.js has',
            );
        }
    }

    /**
     * The provenance table says which release the file came from and its
     * SHA-256. Both are how someone checks the copy against Web eID's own
     * release rather than against this repository.
     */
    public function testTheVendoredScriptMatchesTheDigestItsProvenanceRecords(): void
    {
        $contents = self::read(self::WEB_EID_JS);

        self::assertStringContainsString(
            hash('sha256', $contents),
            self::read('examples/demo-app/README.md'),
            'the recorded SHA-256 is not the one web-eid.js has',
        );
        self::assertStringContainsString(
            'VERSION: "2.1.0"',
            $contents,
            'the file no longer declares the version its provenance records',
        );
    }

    // --- the trust anchors ---------------------------------------------------

    /**
     * The certificates that verify the European list of trusted lists are the
     * whole trust decision, and their README tells the reader to check each one
     * against the Official Journal by its SHA-256. A table that has drifted
     * from the files sends them to check the wrong thing.
     *
     * @param string $file a certificate the library ships
     */
    #[DataProvider('euSignerCertificates')]
    public function testEveryEuSignerMatchesTheDigestItsReadmeRecords(string $file): void
    {
        $certificate = Certificate::fromPem(Resources::read('trust/eu/' . $file));
        $digest = bin2hex($certificate->fingerprint());

        self::assertStringContainsString(
            \sprintf('| `%s` | `%s` |', $file, $digest),
            Resources::read('trust/eu/README.md'),
            $file . ' does not have the digest the README records for it',
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function euSignerCertificates(): iterable
    {
        for ($i = 1; $i <= 6; ++$i) {
            $file = \sprintf('lotl-signer-%d.pem', $i);
            yield $file => [$file];
        }
    }

    /**
     * The set is shipped whole, so a seventh file nobody wrote a row for, or a
     * row for a file that was removed, is a thing to notice.
     */
    public function testTheReadmeDescribesEveryCertificateShippedAndNoOther(): void
    {
        $shipped = glob(self::root() . '/resources/trust/eu/*.pem');
        self::assertIsArray($shipped);
        $names = array_map(static fn(string $path): string => basename($path), $shipped);
        sort($names);

        self::assertSame(iterator_to_array(self::euSignerNames()), $names, 'the shipped certificates are not the ones the tests know about');

        $readme = Resources::read('trust/eu/README.md');
        self::assertSame(
            \count($names),
            preg_match_all('/^\| `lotl-signer-\d+\.pem` \| `[0-9a-f]{64}` \|/m', $readme),
            'the README has a row for each shipped certificate and no other',
        );
    }

    /**
     * @return iterable<string>
     */
    private static function euSignerNames(): iterable
    {
        foreach (self::euSignerCertificates() as $row) {
            yield $row[0];
        }
    }
}
