<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Http;

/**
 * PHP's built-in web server on the loopback address, for the few tests that
 * need a real socket: what the cURL client does with an answer too large to
 * accept, and what the demo application answers over HTTP.
 *
 * The suite stays offline. The server listens on 127.0.0.1 only, on a port the
 * operating system chose, and answers from tests/fixtures/http/router.php or
 * from the directory it was given. Start it once per test class and stop it in
 * tearDownAfterClass().
 */
final class LocalHttpServer
{
    private const ATTEMPTS = 3;

    private const READY_WITHIN_SECONDS = 5.0;

    /** @var resource|null */
    private $process;

    /**
     * @param resource $process
     */
    private function __construct($process, public readonly string $url)
    {
        $this->process = $process;
    }

    public function __destruct()
    {
        $this->stop();
    }

    /**
     * @param string|null           $documentRoot a directory to serve, as `php -S -t` does; the test router's answers
     *                                            when null
     * @param array<string, string> $environment  variables for the server, on top of this process's own. A value
     *                                            must not be empty: on Windows the server would see it as unset
     * @param string|null           $router       with a document root, a script that sees every request, as the last
     *                                            argument of `php -S` is
     * @param array<string, string> $ini          settings for the server, as `php -d` gives them
     */
    public static function start(?string $documentRoot = null, array $environment = [], ?string $router = null, array $ini = []): self
    {
        $settings = [];
        foreach ($ini as $name => $value) {
            $settings[] = '-d';
            $settings[] = $name . '=' . $value;
        }
        $serve = $documentRoot === null
            ? [\dirname(__DIR__, 2) . '/fixtures/http/router.php']
            : ['-t', $documentRoot, ...($router === null ? [] : [$router])];
        $nowhere = PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null';
        $failure = 'it was not tried';
        for ($attempt = 1; $attempt <= self::ATTEMPTS; ++$attempt) {
            // Another process can take the port between choosing it and the
            // server binding it, which is what the retries are for.
            $port = self::freePort();
            $process = proc_open(
                [PHP_BINARY, ...$settings, '-S', '127.0.0.1:' . $port, ...$serve],
                [0 => ['file', $nowhere, 'r'], 1 => ['file', $nowhere, 'w'], 2 => ['file', $nowhere, 'w']],
                $pipes,
                null,
                $environment === [] ? null : [...getenv(), ...$environment],
            );
            if (!\is_resource($process)) {
                $failure = 'proc_open() failed';

                continue;
            }
            if (self::listening($process, $port)) {
                return new self($process, 'http://127.0.0.1:' . $port);
            }
            proc_terminate($process);
            proc_close($process);
            $failure = \sprintf('nothing answered on port %d', $port);
        }

        throw new \RuntimeException('Could not start the local HTTP server: ' . $failure);
    }

    public function stop(): void
    {
        if ($this->process === null) {
            return;
        }
        proc_terminate($this->process);
        proc_close($this->process);
        $this->process = null;
    }

    private static function freePort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errorCode, $errorMessage);
        if ($socket === false) {
            throw new \RuntimeException('Could not find a free port: ' . $errorMessage);
        }
        $name = stream_socket_get_name($socket, false);
        fclose($socket);
        if ($name === false || preg_match('/:(\d+)$/', $name, $matches) !== 1) {
            throw new \RuntimeException('Could not read the port the operating system chose');
        }

        return (int) $matches[1];
    }

    /**
     * @param resource $process
     */
    private static function listening($process, int $port): bool
    {
        $deadline = microtime(true) + self::READY_WITHIN_SECONDS;
        while (microtime(true) < $deadline) {
            // A server that could not bind the port exits, and whatever took
            // the port instead must not be mistaken for it.
            if (!proc_get_status($process)['running']) {
                return false;
            }
            $connection = @fsockopen('127.0.0.1', $port, $errorCode, $errorMessage, 0.2);
            if ($connection !== false) {
                fclose($connection);

                return true;
            }
            usleep(50_000);
        }

        return false;
    }
}
