<?php

declare(strict_types=1);

/**
 * The demo's front controller: routing, and nothing else.
 *
 * Run it with the built-in server:
 *
 *   php -S localhost:8080 -t examples/demo-app/public
 *
 * The ID card needs HTTPS, because the Web eID extension refuses to work on an
 * insecure origin. See the README beside this file.
 */

use Allkiri\Demo\App;

require __DIR__ . '/../../../vendor/autoload.php';
require __DIR__ . '/../config.php';
require __DIR__ . '/../app.php';

session_start();

$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$path = (string) parse_url(is_string($requestUri) ? $requestUri : '/', PHP_URL_PATH);

/**
 * Everything except the page and the assets is JSON.
 *
 * @return array<string, mixed>
 */
function body(): array
{
    $raw = (string) file_get_contents('php://input');
    if ($raw === '') {
        return [];
    }
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        return [];
    }

    $request = [];
    foreach ($decoded as $key => $value) {
        $request[(string) $key] = $value;
    }

    return $request;
}

/**
 * One entry of $_FILES, in the shape the application expects.
 *
 * @return array{name?: string, tmp_name?: string}
 */
function upload(string $field): array
{
    $file = $_FILES[$field] ?? null;
    if (!is_array($file)) {
        return [];
    }

    return [
        'name' => is_string($file['name'] ?? null) ? $file['name'] : '',
        'tmp_name' => is_string($file['tmp_name'] ?? null) ? $file['tmp_name'] : '',
    ];
}

function send(mixed $payload, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    exit;
}

// Static assets are served straight from the library, so the demo uses the same
// files an application would. Nothing here needs the configuration.
$assets = [
    '/allkiri.js' => __DIR__ . '/../../../assets/allkiri.js',
    '/allkiri-qr.js' => __DIR__ . '/../../../assets/allkiri-qr.js',
];
if (isset($assets[$path])) {
    header('Content-Type: application/javascript; charset=utf-8');
    readfile($assets[$path]);
    exit;
}

// The first thing that can go wrong is the configuration, and in live mode it
// is meant to: a missing credential stops the application here rather than
// halfway through someone's signature. Show the reason instead of a blank 500.
try {
    $app = new App();
} catch (Throwable $error) {
    if (str_starts_with($path, '/api/')) {
        send(['error' => $error->getMessage(), 'type' => $error::class], 500);
    }
    http_response_code(500);
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><meta charset="utf-8"><title>allkiri demo</title>'
        . '<h1 style="font:600 1.2rem system-ui">This demo is not configured</h1>'
        . '<pre style="font:14px/1.6 ui-monospace,monospace;white-space:pre-wrap">'
        . htmlspecialchars($error->getMessage(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
        . '</pre>';
    exit;
}

if ($path === '/' || $path === '/index.php') {
    $config = $app->config();
    header('Content-Type: text/html; charset=utf-8');
    require __DIR__ . '/../views/page.php';
    exit;
}

try {
    $answer = match ($path) {
        // Signing in
        '/api/card/challenge' => $app->cardChallenge(),
        '/api/card/login' => $app->cardLogin(body()),
        '/api/mobile-id/login/start' => $app->mobileIdLoginStart(body()),
        '/api/mobile-id/login/poll' => $app->mobileIdLoginPoll(),
        '/api/smart-id/login/start' => $app->smartIdLoginStart(body()),
        '/api/smart-id/login/poll' => $app->smartIdLoginPoll(),

        // Signing a file
        '/api/upload' => $app->upload(upload('file')),
        '/api/mobile-id/sign/start' => $app->mobileIdSignStart(body()),
        '/api/mobile-id/sign/poll' => $app->mobileIdSignPoll(),
        '/api/smart-id/sign/start' => $app->smartIdSignStart(body()),
        '/api/smart-id/sign/poll' => $app->smartIdSignPoll(),
        '/api/card/sign/prepare' => $app->cardSignPrepare(body()),
        '/api/card/sign/complete' => $app->cardSignComplete(body()),
        '/api/archive' => $app->archive(),

        // Validating
        '/api/validate' => $app->validate(upload('file')),

        default => null,
    };
} catch (Throwable $error) {
    // A demo says what went wrong. A real application would log this and show
    // the person something kinder, and would take care not to reveal whether an
    // account exists.
    send(['error' => $error->getMessage(), 'type' => $error::class], 400);
}

if ($answer === null) {
    if ($path === '/api/download') {
        header('Content-Type: application/vnd.etsi.asic-e+zip');
        header('Content-Disposition: attachment; filename="signed.asice"');
        echo $app->download();
        exit;
    }
    send(['error' => 'No such endpoint'], 404);
}

send($answer);
