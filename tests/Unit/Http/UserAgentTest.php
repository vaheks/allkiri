<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Http;

use Allkiri\Http\UserAgent;
use Composer\InstalledVersions;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * #11: the version sent to SK, RIA and Zetes was a constant that said
 * 0.1.0-dev through five releases. It now comes from what Composer installed.
 */
#[CoversClass(UserAgent::class)]
final class UserAgentTest extends TestCase
{
    /**
     * @return iterable<string, array{?string, ?string, string}>
     */
    public static function installs(): iterable
    {
        $commit = 'db35538a5ae4c8504bd877fe15abbbb572406e0c';

        yield 'a tagged pre-release' => ['0.5.0-alpha.1', $commit, '0.5.0-alpha.1'];
        yield 'a tagged release' => ['1.0.0', $commit, '1.0.0'];
        yield 'a branch' => ['dev-main', $commit, 'dev-main+db35538'];
        yield 'a branch alias' => ['1.x-dev', $commit, '1.x-dev+db35538'];
        yield 'a branch whose commit is not known' => ['dev-main', null, 'dev-main'];
        yield 'a branch with a slash in its name' => ['dev-feature/zip', $commit, 'dev-feature-zip+db35538'];
        yield 'nothing Composer can say' => [null, null, UserAgent::UNKNOWN_VERSION];
        yield 'an empty version' => ['', $commit, UserAgent::UNKNOWN_VERSION];
    }

    #[DataProvider('installs')]
    public function testTheVersionComesFromWhatComposerInstalled(?string $prettyVersion, ?string $reference, string $expected): void
    {
        self::assertSame($expected, UserAgent::versionFrom($prettyVersion, $reference));
    }

    /**
     * Whatever this checkout was installed as, the version is Composer's answer
     * about it, not a constant.
     */
    public function testTheVersionIsWhatComposerSaysAboutThisInstall(): void
    {
        self::assertTrue(InstalledVersions::isInstalled(UserAgent::PACKAGE));
        self::assertSame(
            UserAgent::versionFrom(InstalledVersions::getPrettyVersion(UserAgent::PACKAGE), InstalledVersions::getReference(UserAgent::PACKAGE)),
            UserAgent::version(),
        );
        self::assertNotSame('0.1.0-dev', UserAgent::version());
    }

    public function testTheUserAgentNamesTheLibraryItsVersionAndWhereItLives(): void
    {
        self::assertSame('allkiri/' . UserAgent::version() . ' (+https://github.com/vaheks/allkiri)', UserAgent::default());
        self::assertMatchesRegularExpression('#^allkiri/[!\#$%&\'*+\-.^_`|~0-9A-Za-z]+ \(\+https://github\.com/vaheks/allkiri\)$#', UserAgent::default());
    }
}
