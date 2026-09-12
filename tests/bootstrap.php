<?php

declare(strict_types=1);

/**
 * The test suite's bootstrap: the autoloader, and a .env file if there is one.
 *
 * The unit suite needs neither, and must keep working with neither: it is
 * offline and deterministic by design. The .env is for the integration suite and
 * the live smoke test, which need credentials that cannot be committed, and
 * which are tedious to export by hand on Windows.
 *
 * The demo application has its own copy of this reader in
 * examples/demo-app/config.php, because neither half should have to require the
 * other, and the library itself reads no environment variables at all.
 */

require __DIR__ . '/../vendor/autoload.php';

/**
 * KEY=VALUE a line, # comments, optional surrounding quotes. Anything already
 * in the real environment wins, so an exported variable is never quietly
 * overridden by a file.
 */
(static function (string $path): void {
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
        if (strlen($value) >= 2 && ($value[0] === '"' || $value[0] === "'") && $value[-1] === $value[0]) {
            $value = substr($value, 1, -1);
        }
        if ($name !== '' && getenv($name) === false) {
            putenv($name . '=' . $value);
        }
    }
})(__DIR__ . '/../.env');
