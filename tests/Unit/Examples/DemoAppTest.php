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
 * Everything here stays on 127.0.0.1 in demo mode, and no call reaches SK.
 */
#[CoversNothing]
final class DemoAppTest extends TestCase
{
    private static ?LocalHttpServer $server = null;

    private static string $log = '';

    public static function setUpBeforeClass(): void
    {
        self::$log = sys_get_temp_dir() . '/allkiri-demo-test-' . bin2hex(random_bytes(4)) . '.log';
        // Pinned rather than inherited, so a local .env can neither put the demo
        // in live mode nor send its log to a file someone reads.
        self::$server = LocalHttpServer::start(\dirname(__DIR__, 3) . '/examples/demo-app/public', [
            'ALLKIRI_MODE' => 'demo',
            'ALLKIRI_LOG' => self::$log,
            'ALLKIRI_LOG_HTTP' => '0',
            'ALLKIRI_LOG_PERSONAL_DATA' => '0',
        ]);
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
        $storage = \dirname(__DIR__, 3) . '/examples/demo-app/var';
        $before = self::containersIn($storage);
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
        $created = array_values(array_diff(self::containersIn($storage), $before));
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

        $cookie = '';
        foreach ($page['headers']['set-cookie'] ?? [] as $header) {
            if (preg_match('/^(PHPSESSID=[^;]+)/', $header, $match) === 1) {
                $cookie = $match[1];
            }
        }
        self::assertNotSame('', $cookie, 'the page starts a session');
        self::assertSame(1, preg_match('/<meta name="csrf-token" content="([0-9a-f]{64})">/', $page['body'], $token), 'the page carries a token');

        return ['cookie' => $cookie, 'token' => $token[1]];
    }

    /**
     * @param non-empty-string      $method
     * @param array<string, string> $headers an empty value sends the header empty
     *
     * @return array{status: int, headers: array<string, list<string>>, body: string}
     */
    private static function request(string $method, string $path, array $headers = [], ?string $body = null): array
    {
        $server = self::$server ?? throw new \LogicException('The demo is not running');
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
