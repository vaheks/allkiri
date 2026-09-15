<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Examples;

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
        self::$server = LocalHttpServer::start(self::DOCUMENT_ROOT, ['ALLKIRI_MODE' => 'demo'] + self::quietLog());
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
        $boundary = 'allkiri-' . bin2hex(random_bytes(8));
        $body = '--' . $boundary . "\r\n"
            . "Content-Disposition: form-data; name=\"file\"; filename=\"leping.txt\"\r\n"
            . "Content-Type: text/plain\r\n\r\n"
            . "Tere, allkiri!\r\n"
            . '--' . $boundary . "--\r\n";

        $upload = self::request('POST', '/api/upload', [
            'Cookie' => $page['cookie'],
            'X-CSRF-Token' => $page['token'],
            'Content-Type' => 'multipart/form-data; boundary=' . $boundary,
        ], $body);

        self::assertSame(200, $upload['status'], $upload['body']);
        $created = array_values(array_diff(self::containersIn(self::STORAGE), $before));
        self::assertCount(1, $created, 'the container is kept in the demo\'s own folder');
        try {
            self::assertMatchesRegularExpression('/^[0-9a-f]{32}\.asice$/', basename($created[0]));
            self::assertStringNotContainsString($sessionId, $created[0]);

            $download = self::request('GET', '/api/download', ['Cookie' => $page['cookie']]);
            self::assertSame(200, $download['status']);
            self::assertStringStartsWith("PK\x03\x04", $download['body']);
        } finally {
            unlink($created[0]);
        }
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
        $live = LocalHttpServer::start(self::DOCUMENT_ROOT, [
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
