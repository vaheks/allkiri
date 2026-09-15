<?php

declare(strict_types=1);

/**
 * The demo's front controller: routing, and the checks every call passes before
 * it reaches the application.
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

// No page of this demo is meant to be shown inside someone else's. A framed
// page's own buttons need no token, and one of them buys a timestamp.
header("Content-Security-Policy: frame-ancestors 'none'");
header('X-Frame-Options: DENY');

$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$path = (string) parse_url(is_string($requestUri) ? $requestUri : '/', PHP_URL_PATH);
$requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$method = is_string($requestMethod) ? strtoupper($requestMethod) : 'GET';

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

function refuseMethod(string $allowed): never
{
    header('Allow: ' . $allowed);
    send(['error' => 'Use ' . $allowed . ' for this address'], 405);
}

/**
 * The token the page sends back with every call that changes something, made
 * once per browser session.
 */
function csrfToken(): string
{
    $token = $_SESSION['csrf'] ?? null;
    if (!is_string($token) || $token === '') {
        $token = bin2hex(random_bytes(32));
        $_SESSION['csrf'] = $token;
    }

    return $token;
}

/**
 * Whether the call carries this browser session's token. A session that was
 * never given one matches nothing, so an empty header cannot pass.
 */
function carriesCsrfToken(): bool
{
    $expected = $_SESSION['csrf'] ?? null;
    $given = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;

    return is_string($expected) && $expected !== '' && is_string($given) && hash_equals($expected, $given);
}

// Static assets are served straight from the library, so the demo uses the same
// files an application would. Nothing here needs the configuration or the
// session, so a script request neither waits for a poll holding the session
// lock nor sets a cookie.
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

// The session cookie is out of reach of scripts and of other sites' requests,
// and PHP refuses a session id it did not make. It is Secure whenever the page
// came over HTTPS, and always in live mode, which has no business running over
// anything else. The demo also runs over plain HTTP for Mobile-ID and Smart-ID,
// where a Secure cookie would never come back.
$https = $_SERVER['HTTPS'] ?? '';
session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Lax',
    'cookie_secure' => (is_string($https) && $https !== '' && strtolower($https) !== 'off') || $app->config()->isLive(),
    'use_strict_mode' => true,
    'use_only_cookies' => true,
]);

if ($path === '/' || $path === '/index.php') {
    if ($method !== 'GET') {
        header('Allow: GET');
        http_response_code(405);
        exit;
    }
    $config = $app->config();
    $csrfToken = csrfToken();
    header('Content-Type: text/html; charset=utf-8');
    require __DIR__ . '/../views/page.php';
    exit;
}

// Reading the finished container is the one call that changes nothing, and the
// only GET. A browser follows it as a link, so it carries no token.
if ($path === '/api/download') {
    if ($method !== 'GET') {
        refuseMethod('GET');
    }
    try {
        $signed = $app->download();
    } catch (Throwable $error) {
        send(['error' => $error->getMessage(), 'type' => $error::class], 400);
    }
    header('Content-Type: application/vnd.etsi.asic-e+zip');
    header('Content-Disposition: attachment; filename="signed.asice"');
    echo $signed;
    exit;
}

// Everything else changes something: it starts a request to someone's phone,
// replaces a challenge, finishes a session or buys a timestamp. So it is a POST
// carrying the page's token. A form on another site can post here with the
// visitor's cookie, but it cannot read the token or add a header.
$endpoints = [
    // Signing in
    '/api/card/challenge' => static fn(): array => $app->cardChallenge(),
    '/api/card/login' => static fn(): array => $app->cardLogin(body()),
    '/api/mobile-id/login/start' => static fn(): array => $app->mobileIdLoginStart(body()),
    '/api/mobile-id/login/poll' => static fn(): array => $app->mobileIdLoginPoll(),
    '/api/smart-id/login/start' => static fn(): array => $app->smartIdLoginStart(body()),
    '/api/smart-id/login/poll' => static fn(): array => $app->smartIdLoginPoll(),

    // Signing a file
    '/api/upload' => static fn(): array => $app->upload(upload('file')),
    '/api/mobile-id/sign/start' => static fn(): array => $app->mobileIdSignStart(body()),
    '/api/mobile-id/sign/poll' => static fn(): array => $app->mobileIdSignPoll(),
    '/api/smart-id/sign/start' => static fn(): array => $app->smartIdSignStart(body()),
    '/api/smart-id/sign/poll' => static fn(): array => $app->smartIdSignPoll(),
    '/api/card/sign/prepare' => static fn(): array => $app->cardSignPrepare(body()),
    '/api/card/sign/complete' => static fn(): array => $app->cardSignComplete(body()),
    '/api/archive' => static fn(): array => $app->archive(),

    // Validating
    '/api/validate' => static fn(): array => $app->validate(upload('file')),
];

$endpoint = $endpoints[$path] ?? null;
if ($endpoint === null) {
    send(['error' => 'No such endpoint'], 404);
}
if ($method !== 'POST') {
    refuseMethod('POST');
}
// Before anything reads the request.
if (!carriesCsrfToken()) {
    send(['error' => 'This call did not carry the page\'s token. Reload the page and try again.'], 403);
}

try {
    $answer = $endpoint();
} catch (Throwable $error) {
    // A demo says what went wrong. A real application would log this and show
    // the person something kinder, and would take care not to reveal whether an
    // account exists.
    send(['error' => $error->getMessage(), 'type' => $error::class], 400);
}

send($answer);
