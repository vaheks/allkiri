<?php

declare(strict_types=1);

namespace Allkiri\Http;

use Composer\InstalledVersions;

/**
 * What allkiri tells the services it calls about itself. SK, RIA and Zetes see
 * it, so their operators can tell which client, and which release of it, sent a
 * request.
 *
 * The version is read from Composer, which knows what was installed, rather
 * than kept in a constant that has to be remembered at every release.
 */
final class UserAgent
{
    public const PACKAGE = 'vaheks/allkiri';

    /** When allkiri was not installed through Composer, or Composer cannot say. */
    public const UNKNOWN_VERSION = 'unknown';

    private function __construct() {}

    /**
     * The installed version: a release's tag, such as "1.0.0", or for a branch
     * install the branch and the first seven characters of the commit, such as
     * "dev-main+db35538".
     */
    public static function version(): string
    {
        if (!class_exists(InstalledVersions::class) || !InstalledVersions::isInstalled(self::PACKAGE)) {
            return self::UNKNOWN_VERSION;
        }

        return self::versionFrom(InstalledVersions::getPrettyVersion(self::PACKAGE), InstalledVersions::getReference(self::PACKAGE));
    }

    /**
     * @return non-empty-string
     */
    public static function default(): string
    {
        return 'allkiri/' . self::version() . ' (+https://github.com/vaheks/allkiri)';
    }

    /**
     * @internal
     */
    public static function versionFrom(?string $prettyVersion, ?string $reference): string
    {
        if ($prettyVersion === null || $prettyVersion === '') {
            return self::UNKNOWN_VERSION;
        }
        $version = $prettyVersion;
        $isBranch = str_starts_with($version, 'dev-') || str_ends_with($version, '-dev');
        if ($isBranch && $reference !== null && preg_match('/^[0-9a-f]{40}\z/', $reference) === 1) {
            $version .= '+' . substr($reference, 0, 7);
        }

        // A product version in a User-Agent is an RFC 9110 token, and a branch
        // name can hold characters that are not allowed there, such as "/".
        return preg_replace('/[^!#$%&\'*+\-.^_`|~0-9A-Za-z]/', '-', $version) ?? self::UNKNOWN_VERSION;
    }
}
