<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Examples;

use Allkiri\Container\AsicReader;
use Allkiri\Container\DataFile;
use Allkiri\Tests\Support\Http\LocalHttpServer;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * The demo application, run the way its README runs it and asked over HTTP.
 *
 * It is the code people copy, so what it refuses is tested like the library.
 * Everything here stays on 127.0.0.1, and no call reaches SK.
 */
#[CoversNothing]
final class DemoAppTest extends TestCase
{
    private const DOCUMENT_ROOT = __DIR__ . '/../../../examples/demo-app/public';

    private const STORAGE = __DIR__ . '/../../../examples/demo-app/var';

    private static ?LocalHttpServer $server = null;

    private static string $log = '';

    public static function setUpBeforeClass(): void
    {
        self::$log = sys_get_temp_dir() . '/allkiri-demo-test-' . bin2hex(random_bytes(4)) . '.log';
        self::$server = self::startDemo(['ALLKIRI_MODE' => 'demo'] + self::quietLog());
    }

    public static function tearDownAfterClass(): void
    {
        self::$server?->stop();
        self::$server = null;
        if (is_file(self::$log)) {
            unlink(self::$log);
        }
    }

    public function testACallThatChangesSomethingMustBeAPost(): void
    {
        $archive = self::request('GET', '/api/archive');
        self::assertSame(405, $archive['status'], 'a GET that would buy a timestamp');
        self::assertSame(['POST'], $archive['headers']['allow'] ?? []);
        self::assertSame(['application/json; charset=utf-8'], $archive['headers']['content-type'] ?? []);

        $download = self::request('POST', '/api/download');
        self::assertSame(405, $download['status']);
        self::assertSame(['GET'], $download['headers']['allow'] ?? []);
    }

    public function testACallWithoutThePagesTokenIsRefused(): void
    {
        $cookie = ['Cookie' => self::openPage()['cookie']];

        self::assertSame(403, self::request('POST', '/api/card/challenge', $cookie)['status'], 'no token');
        self::assertSame(403, self::request('POST', '/api/card/challenge', $cookie + ['X-CSRF-Token' => str_repeat('0', 64)])['status'], 'a wrong token');
        // What a form on another site can send: the visitor's cookie, a
        // text/plain body that parses as JSON, and no header of its own.
        $form = self::request('POST', '/api/card/challenge', $cookie + ['Content-Type' => 'text/plain'], '{"token":"x"}');
        self::assertSame(403, $form['status'], 'a cross-site form post');
        self::assertSame(['application/json; charset=utf-8'], $form['headers']['content-type'] ?? []);
    }

    public function testASessionThatWasNeverGivenATokenMatchesNothing(): void
    {
        self::assertSame(403, self::request('POST', '/api/card/challenge', ['X-CSRF-Token' => ''])['status']);
    }

    public function testThePagesOwnTokenIsAccepted(): void
    {
        $page = self::openPage();

        $challenge = self::request('POST', '/api/card/challenge', ['Cookie' => $page['cookie'], 'X-CSRF-Token' => $page['token']]);

        self::assertSame(200, $challenge['status'], $challenge['body']);
        self::assertMatchesRegularExpression('/"nonce":"[^"]+"/', $challenge['body']);
    }

    public function testNoResponseCanBeFramed(): void
    {
        foreach (['the page' => self::request('GET', '/'), 'a refusal' => self::request('GET', '/api/archive')] as $what => $response) {
            self::assertSame(["frame-ancestors 'none'"], $response['headers']['content-security-policy'] ?? [], $what);
            self::assertSame(['DENY'], $response['headers']['x-frame-options'] ?? [], $what);
        }
    }

    public function testDownloadingBeforeUploadingIsAnError(): void
    {
        $download = self::request('GET', '/api/download', ['Cookie' => self::openPage()['cookie']]);

        self::assertSame(400, $download['status'], $download['body']);
        self::assertSame(['application/json; charset=utf-8'], $download['headers']['content-type'] ?? []);
        self::assertStringContainsString('Upload a file first', $download['body']);
    }

    public function testAnUploadIsKeptUnderARandomNameNotTheSessionId(): void
    {
        $page = self::openPage();
        $sessionId = substr($page['cookie'], \strlen('PHPSESSID='));
        $before = self::containersIn(self::STORAGE);

        $upload = self::upload($page, [['leping.txt', "Tere, allkiri!\r\n"], ['lisa.txt', "Teine fail\r\n"]]);

        self::assertSame(200, $upload['status'], $upload['body']);
        $created = array_values(array_diff(self::containersIn(self::STORAGE), $before));
        self::assertCount(1, $created, 'the container is kept in the demo\'s own folder');
        try {
            self::assertMatchesRegularExpression('/^[0-9a-f]{32}\.asice$/', basename($created[0]));
            self::assertStringNotContainsString($sessionId, $created[0]);

            $download = self::request('GET', '/api/download', ['Cookie' => $page['cookie']]);
            self::assertSame(200, $download['status']);
            // Every file chosen, in one container.
            $container = (new AsicReader())->read($download['body']);
            self::assertSame(
                ['leping.txt' => "Tere, allkiri!\r\n", 'lisa.txt' => "Teine fail\r\n"],
                array_column(array_map(static fn(DataFile $file): array => [$file->name, $file->content], $container->dataFiles), 1, 0),
            );
        } finally {
            unlink($created[0]);
        }
    }

    public function testTwoFilesOfTheSameNameAreRefused(): void
    {
        $page = self::openPage();
        $before = self::containersIn(self::STORAGE);

        $upload = self::upload($page, [['leping.txt', 'first'], ['leping.txt', 'second']]);

        self::assertSame(400, $upload['status'], $upload['body']);
        self::assertStringContainsString('Duplicate data file name', $upload['body']);
        self::assertSame($before, self::containersIn(self::STORAGE), 'nothing is kept');
    }

    public function testThePageOffersBothSmartIdSignIns(): void
    {
        $page = self::request('GET', '/');

        self::assertStringContainsString('id="sid-login"', $page['body'], 'by identity code');
        self::assertStringContainsString('id="sid-device-login"', $page['body'], 'by QR code or by the app on the same phone');
        self::assertStringContainsString('<script src="/allkiri-qr.js"></script>', $page['body'], 'the encoder the QR code needs');
        self::assertStringContainsString("linkUrl: '/api/smart-id/login/qr/link'", $page['body']);
    }

    /**
     * The link endpoint only ever answers for a session this browser started.
     * The session secret that signs a link never leaves the server, so there is
     * nothing else it could build one from.
     */
    public function testAQrLinkNeedsASignInInProgress(): void
    {
        $page = self::openPage();

        $link = self::request('POST', '/api/smart-id/login/qr/link', ['Cookie' => $page['cookie'], 'X-CSRF-Token' => $page['token']]);

        self::assertSame(400, $link['status'], $link['body']);
        self::assertStringContainsString('No QR sign-in is in progress', $link['body']);
        self::assertSame(403, self::request('POST', '/api/smart-id/login/qr/link', ['Cookie' => $page['cookie']])['status'], 'no token');
        self::assertSame(405, self::request('GET', '/api/smart-id/login/qr/link')['status']);

        $poll = self::request('POST', '/api/smart-id/login/qr/poll', ['Cookie' => $page['cookie'], 'X-CSRF-Token' => $page['token']]);
        self::assertSame(400, $poll['status'], $poll['body']);
        self::assertStringContainsString('No QR sign-in is in progress', $poll['body']);
    }

    /**
     * The Smart-ID app opens the callback as a plain link, so it carries no
     * token. What it proves instead is checked against the sign-in this browser
     * started, and a browser that started none gets nothing, whatever the URL
     * says.
     */
    public function testACallbackWithoutASignInInThisBrowserSignsNobodyIn(): void
    {
        $page = self::openPage();

        $callback = self::request('GET', '/smart-id/callback?value=RrKjjT4aggzu27YBddX1bQ&sessionSecretDigest=U4CKK13H1XFiyBofev9asqrzIrY5_Gszi_nL_zDKkBc&userChallengeVerifier=XtPfaGa8JnGtYrJjboooUf0KfY9sMEHrWFpSQrsUv9c', ['Cookie' => $page['cookie']]);

        self::assertSame(400, $callback['status'], $callback['body']);
        self::assertSame(['text/html; charset=utf-8'], $callback['headers']['content-type'] ?? []);
        self::assertStringContainsString('Not signed in', $callback['body']);
        self::assertStringContainsString('No Smart-ID sign-in is waiting in this browser', $callback['body']);
        self::assertStringContainsString('start again from your default browser', $callback['body']);
        // The URL carries what proves a sign-in; the page passes it nowhere.
        self::assertSame(['no-referrer'], $callback['headers']['referrer-policy'] ?? []);
        self::assertSame(['no-store'], $callback['headers']['cache-control'] ?? []);
        self::assertSame(405, self::request('POST', '/smart-id/callback', ['Cookie' => $page['cookie'], 'X-CSRF-Token' => $page['token']])['status']);

        $state = self::request('POST', '/api/smart-id/login/qr/state', ['Cookie' => $page['cookie'], 'X-CSRF-Token' => $page['token']]);
        self::assertSame(400, $state['status'], $state['body']);
        self::assertStringContainsString('No Smart-ID sign-in is in progress', $state['body']);
    }

    /**
     * Signing in replaces the session id while the page may still have a call
     * on its way with the old one, as a QR code's link requests do every second.
     * PHP answers that call with a fresh, empty session. If its cookie reached
     * the browser after the signed-in one, the person would be signed out and
     * every later call refused.
     */
    public function testACallRefusedForItsTokenLeavesTheCookieAlone(): void
    {
        $replaced = bin2hex(random_bytes(16));

        $refused = self::request('POST', '/api/smart-id/login/qr/link', ['Cookie' => 'PHPSESSID=' . $replaced, 'X-CSRF-Token' => str_repeat('0', 64)]);

        self::assertSame(403, $refused['status'], $refused['body']);
        self::assertSame([], $refused['headers']['set-cookie'] ?? []);
    }

    public function testThePageLoadsAPinnedCopyOfWebEidJs(): void
    {
        $page = self::request('GET', '/');

        self::assertStringNotContainsString('cdn.jsdelivr.net', $page['body'], 'no CDN serves web-eid.js');
        self::assertSame(1, preg_match('#<script src="/vendor/web-eid\.js" integrity="(sha384-[A-Za-z0-9+/=]+)"></script>#', $page['body'], $tag), 'the page loads its own copy, with a hash');

        $file = (string) file_get_contents(self::DOCUMENT_ROOT . '/vendor/web-eid.js');
        self::assertSame('sha384-' . base64_encode(hash('sha384', $file, true)), $tag[1], 'the hash is the committed file\'s');
        self::assertStringStartsWith("/**\n * MIT License", $file, 'the licence travels with the copy');

        $served = self::request('GET', '/vendor/web-eid.js');
        self::assertSame(200, $served['status']);
        self::assertSame($file, $served['body']);
    }

    public function testTheSessionCookieIsHiddenFromScriptsAndOtherSites(): void
    {
        $cookie = self::sessionCookieOf(self::request('GET', '/'));

        self::assertStringContainsStringIgnoringCase('; HttpOnly', $cookie);
        self::assertStringContainsStringIgnoringCase('; SameSite=Lax', $cookie);
        self::assertStringNotContainsStringIgnoringCase('; Secure', $cookie, 'over plain HTTP a Secure cookie would never come back');
    }

    public function testASessionIdTheServerDidNotIssueIsReplaced(): void
    {
        // Fresh each run: a fixed id, once accepted by a server without strict
        // mode, would exist in the session store and rightly be kept.
        $planted = bin2hex(random_bytes(16));

        $cookie = self::sessionCookieOf(self::request('GET', '/', ['Cookie' => 'PHPSESSID=' . $planted]));

        self::assertStringNotContainsString($planted, $cookie);
    }

    public function testScriptsAreServedWithoutASession(): void
    {
        $script = self::request('GET', '/allkiri.js');

        self::assertSame(200, $script['status']);
        self::assertSame([], $script['headers']['set-cookie'] ?? []);
    }

    public function testLiveModeMarksTheCookieSecure(): void
    {
        // Made-up credentials in the shape live mode demands. Rendering the page
        // calls no service.
        $live = self::startDemo([
            'ALLKIRI_MODE' => 'live',
            'ALLKIRI_MID_RP_UUID' => '5e0b2a3c-7d41-4f6a-9c2e-1b8d4f7a3e65',
            'ALLKIRI_MID_RP_NAME' => 'allkiri test',
            'ALLKIRI_SMARTID_RP_UUID' => '9a4c6e1f-2b3d-4e5f-8a7b-6c5d4e3f2a1b',
            'ALLKIRI_SMARTID_RP_NAME' => 'allkiri test',
            'ALLKIRI_ORIGIN' => 'https://allkiri.test',
        ] + self::quietLog());
        try {
            $page = self::request('GET', '/', [], null, $live);
        } finally {
            $live->stop();
        }

        self::assertSame(200, $page['status'], $page['body']);
        self::assertStringContainsStringIgnoringCase('; Secure', self::sessionCookieOf($page));
    }

    /**
     * The demo as its README starts it: public/ as the document root and
     * index.php as the router, which PHP before 8.4 needs to hand /allkiri.js on.
     *
     * @param array<string, string> $environment
     */
    private static function startDemo(array $environment): LocalHttpServer
    {
        return LocalHttpServer::start(self::DOCUMENT_ROOT, $environment, self::DOCUMENT_ROOT . '/index.php');
    }

    /**
     * Pinned rather than inherited, so a local .env can neither send the demo's
     * log to a file someone reads nor fill it with HTTP transcripts.
     *
     * @return array<string, string>
     */
    private static function quietLog(): array
    {
        return ['ALLKIRI_LOG' => self::$log, 'ALLKIRI_LOG_HTTP' => '0', 'ALLKIRI_LOG_PERSONAL_DATA' => '0'];
    }

    /**
     * Post files as the page does, all under name="files[]".
     *
     * @param array{cookie: string, token: string} $page
     * @param list<array{string, string}>          $files name and content, in order
     *
     * @return array{status: int, headers: array<string, list<string>>, body: string}
     */
    private static function upload(array $page, array $files): array
    {
        $boundary = 'allkiri-' . bin2hex(random_bytes(8));
        $body = '';
        foreach ($files as [$name, $content]) {
            $body .= '--' . $boundary . "\r\n"
                . "Content-Disposition: form-data; name=\"files[]\"; filename=\"" . $name . "\"\r\n"
                . "Content-Type: text/plain\r\n\r\n"
                . $content . "\r\n";
        }
        $body .= '--' . $boundary . "--\r\n";

        return self::request('POST', '/api/upload', [
            'Cookie' => $page['cookie'],
            'X-CSRF-Token' => $page['token'],
            'Content-Type' => 'multipart/form-data; boundary=' . $boundary,
        ], $body);
    }

    /**
     * @return list<string>
     */
    private static function containersIn(string $directory): array
    {
        $found = glob($directory . '/*.asice');

        return $found === false ? [] : $found;
    }

    /**
     * The page as a browser first sees it: the session cookie it sets and the
     * token it carries.
     *
     * @return array{cookie: string, token: string}
     */
    private static function openPage(): array
    {
        $page = self::request('GET', '/');
        self::assertSame(200, $page['status'], $page['body']);
        self::assertSame(1, preg_match('/<meta name="csrf-token" content="([0-9a-f]{64})">/', $page['body'], $token), 'the page carries a token');

        return ['cookie' => explode(';', self::sessionCookieOf($page), 2)[0], 'token' => $token[1]];
    }

    /**
     * @param array{status: int, headers: array<string, list<string>>, body: string} $response
     *
     * @return string the whole Set-Cookie value of the session cookie
     */
    private static function sessionCookieOf(array $response): string
    {
        foreach ($response['headers']['set-cookie'] ?? [] as $header) {
            if (str_starts_with($header, 'PHPSESSID=')) {
                return $header;
            }
        }

        self::fail('The response set no session cookie');
    }

    /**
     * @param non-empty-string      $method
     * @param array<string, string> $headers an empty value sends the header empty
     *
     * @return array{status: int, headers: array<string, list<string>>, body: string}
     */
    private static function request(string $method, string $path, array $headers = [], ?string $body = null, ?LocalHttpServer $server = null): array
    {
        $server ??= self::$server ?? throw new \LogicException('The demo is not running');
        $lines = [];
        foreach ($headers as $name => $value) {
            // curl drops a header given as "Name:", and sends one given as "Name;" empty.
            $lines[] = $value === '' ? $name . ';' : $name . ': ' . $value;
        }

        $handle = curl_init($server->url . $path);
        if ($handle === false) {
            throw new \RuntimeException('curl_init() failed');
        }
        $received = [];
        curl_setopt_array($handle, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_HEADERFUNCTION => static function (\CurlHandle $handle, string $line) use (&$received): int {
                $parts = explode(':', $line, 2);
                if (\count($parts) === 2) {
                    $received[strtolower(trim($parts[0]))][] = trim($parts[1]);
                }

                return \strlen($line);
            },
        ]);
        if ($body !== null) {
            curl_setopt($handle, CURLOPT_POSTFIELDS, $body);
        }
        $answer = curl_exec($handle);
        $status = curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        if (!\is_string($answer) || !\is_int($status)) {
            throw new \RuntimeException('The demo did not answer: ' . curl_error($handle));
        }

        return ['status' => $status, 'headers' => $received, 'body' => $answer];
    }
}
