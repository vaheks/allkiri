<?php

declare(strict_types=1);

/**
 * The router behind tests/Support/Http/LocalHttpServer.
 *
 * /bytes/{n}   n bytes with a Content-Length, which a client can refuse before reading
 * /stream/{n}  n bytes with no length, which a client has to count as they arrive
 * /user-agent  the User-Agent header the request carried
 */

$uri = $_SERVER['REQUEST_URI'] ?? '';
if ($uri === '/user-agent') {
    $agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    header('Content-Type: text/plain');
    echo is_string($agent) ? $agent : '';

    return;
}
if (!is_string($uri) || preg_match('#^/(bytes|stream)/(\d{1,10})$#', $uri, $matches) !== 1) {
    http_response_code(404);

    return;
}

$remaining = (int) $matches[2];
header('Content-Type: application/octet-stream');
if ($matches[1] === 'bytes') {
    header('Content-Length: ' . $remaining);
}
while ($remaining > 0) {
    $piece = min($remaining, 65_536);
    echo str_repeat('x', $piece);
    flush();
    $remaining -= $piece;
}
