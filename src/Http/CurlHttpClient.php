<?php

declare(strict_types=1);

namespace Allkiri\Http;

use Allkiri\Exception\InvalidArgumentException;

/**
 * Default HTTP client on ext-curl.
 *
 * It is the only client that can honour SK's recommended TLS public-key
 * pinning (CURLOPT_PINNEDPUBLICKEY), which is why allkiri ships one instead
 * of requiring a PSR-18 implementation. Redirects are never followed: every
 * endpoint allkiri talks to is an exact, configured URL.
 *
 * Certificate verification is always on. A PHP build with no CA bundle
 * configured (an empty `curl.cainfo`, common on Windows) will fail every
 * HTTPS request with curl error 60; either set `curl.cainfo` in php.ini or
 * pass a bundle path as `$caBundlePath`.
 *
 * Two limits keep a slow or oversized answer from holding a worker. Connecting
 * gets at most ten seconds by default, so an unreachable host fails quickly
 * even when a long poll needs a long overall timeout. And an answer larger
 * than `$maxResponseBytes` is refused: as soon as its length is announced, or
 * as soon as that many bytes have arrived when it is not.
 */
final class CurlHttpClient implements HttpClient
{
    /** The connect timeout when none is given, unless the whole timeout is shorter. */
    private const DEFAULT_CONNECT_TIMEOUT_SECONDS = 10;

    /** cURL takes the size limit as a C long, which is 32 bits on Windows. */
    private const LARGEST_RESPONSE_LIMIT = 2_147_483_647;

    /** @var non-empty-string */
    private readonly string $userAgent;

    /** cURL's pin syntax "sha256//<base64>;sha256//<base64>", or null when nothing is pinned */
    private readonly ?string $pinnedPublicKeyOption;

    /** @var non-empty-string|null */
    private readonly ?string $caBundle;

    private readonly int $connectTimeoutSeconds;

    /**
     * @param string|null  $userAgent             what the services are told about the client;
     *                                            {@see UserAgent::default()} when null
     * @param list<string> $pinnedPublicKeys      base64 SHA-256 hashes of the
     *                                            servers' SubjectPublicKeyInfo, with
     *                                            or without the "sha256//" prefix
     * @param string|null  $caBundlePath          a PEM file of trusted certificate
     *                                            authorities, for builds where PHP
     *                                            has none configured (`curl.cainfo`
     *                                            empty, common on Windows); the
     *                                            system store is used when null
     * @param int|null     $connectTimeoutSeconds how long establishing the connection
     *                                            may take, TLS included; ten seconds,
     *                                            or the whole timeout when that is
     *                                            shorter, when null
     * @param int          $maxResponseBytes      the largest answer accepted
     */
    public function __construct(
        private readonly int $timeoutSeconds = 30,
        ?string $userAgent = null,
        array $pinnedPublicKeys = [],
        ?string $caBundlePath = null,
        ?int $connectTimeoutSeconds = null,
        private readonly int $maxResponseBytes = HttpClient::DEFAULT_MAX_RESPONSE_BYTES,
    ) {
        if ($timeoutSeconds < 1) {
            throw new InvalidArgumentException('Timeout must be at least one second');
        }
        if ($connectTimeoutSeconds !== null && ($connectTimeoutSeconds < 1 || $connectTimeoutSeconds > $timeoutSeconds)) {
            throw new InvalidArgumentException(\sprintf('The connect timeout must be between one second and the whole timeout of %d seconds', $timeoutSeconds));
        }
        if ($maxResponseBytes < 1 || $maxResponseBytes > self::LARGEST_RESPONSE_LIMIT) {
            throw new InvalidArgumentException(\sprintf('The response limit must be between one byte and %d bytes', self::LARGEST_RESPONSE_LIMIT));
        }
        $userAgent ??= UserAgent::default();
        if ($userAgent === '') {
            throw new InvalidArgumentException('User agent must not be empty');
        }
        if ($caBundlePath !== null && ($caBundlePath === '' || !is_file($caBundlePath))) {
            throw new InvalidArgumentException(\sprintf('CA bundle "%s" does not exist', $caBundlePath));
        }
        $this->userAgent = $userAgent;
        $this->caBundle = $caBundlePath;
        $this->pinnedPublicKeyOption = $pinnedPublicKeys === [] ? null : self::pinnedPublicKeyOption($pinnedPublicKeys);
        $this->connectTimeoutSeconds = $connectTimeoutSeconds ?? min(self::DEFAULT_CONNECT_TIMEOUT_SECONDS, $timeoutSeconds);
    }

    public function send(HttpRequest $request): HttpResponse
    {
        $handle = curl_init();
        if ($handle === false) {
            throw new TransportException('curl_init() failed');
        }

        try {
            $responseHeaders = [];
            $body = new BoundedBody($this->maxResponseBytes);
            $options = [
                CURLOPT_URL => $request->url,
                CURLOPT_CUSTOMREQUEST => $request->method,
                CURLOPT_HEADER => false,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_CONNECTTIMEOUT => $this->connectTimeoutSeconds,
                CURLOPT_TIMEOUT => $this->timeoutSeconds,
                // Refuses an announced length before any of the body is read.
                // The write function below catches an answer that announces none.
                CURLOPT_MAXFILESIZE => $this->maxResponseBytes,
                CURLOPT_USERAGENT => $this->userAgent,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
                CURLOPT_HTTPHEADER => self::headerLines($request),
                CURLOPT_HEADERFUNCTION => static function (\CurlHandle $unused, string $line) use (&$responseHeaders): int {
                    $separator = strpos($line, ':');
                    if ($separator !== false) {
                        $name = strtolower(trim(substr($line, 0, $separator)));
                        $value = trim(substr($line, $separator + 1));
                        $responseHeaders[$name] = isset($responseHeaders[$name]) ? $responseHeaders[$name] . ', ' . $value : $value;
                    }

                    return \strlen($line);
                },
                // Taking fewer bytes than were offered makes cURL abort the transfer.
                CURLOPT_WRITEFUNCTION => static fn(\CurlHandle $unused, string $chunk): int => $body->append($chunk) ? \strlen($chunk) : 0,
            ];
            if ($request->body !== '' || $request->method === 'POST') {
                $options[CURLOPT_POSTFIELDS] = $request->body;
            }
            if ($this->pinnedPublicKeyOption !== null) {
                $options[CURLOPT_PINNEDPUBLICKEY] = $this->pinnedPublicKeyOption;
            }
            if ($this->caBundle !== null) {
                $options[CURLOPT_CAINFO] = $this->caBundle;
            }
            if (!curl_setopt_array($handle, $options)) {
                throw new TransportException('curl_setopt_array() rejected the request options: ' . curl_error($handle));
            }

            $completed = curl_exec($handle);
            if ($body->exceeded() || curl_errno($handle) === CURLE_FILESIZE_EXCEEDED) {
                throw TransportException::responseTooLarge($request, $this->maxResponseBytes);
            }
            if ($completed === false) {
                throw new TransportException(\sprintf('%s %s failed: %s (curl error %d)', $request->method, $request->redactedUrl(), curl_error($handle), curl_errno($handle)));
            }
            $status = curl_getinfo($handle, CURLINFO_RESPONSE_CODE);

            return new HttpResponse(\is_int($status) ? $status : 0, $responseHeaders, $body->bytes());
        } finally {
            curl_close($handle);
        }
    }

    /**
     * cURL's pin syntax: "sha256//<base64>;sha256//<base64>".
     *
     * @param non-empty-list<string> $pins
     *
     * @return non-empty-string
     */
    public static function pinnedPublicKeyOption(array $pins): string
    {
        $option = '';
        foreach ($pins as $pin) {
            $option .= ($option === '' ? '' : ';') . self::normalisePin($pin);
        }

        return $option;
    }

    /**
     * @return non-empty-string
     */
    private static function normalisePin(string $pin): string
    {
        $pin = trim($pin);
        if (str_starts_with($pin, 'sha256//')) {
            $pin = substr($pin, 8);
        }
        $decoded = base64_decode($pin, true);
        if ($decoded === false || \strlen($decoded) !== 32) {
            throw new InvalidArgumentException(\sprintf('Pin "%s" is not a base64 SHA-256 hash', $pin));
        }

        return 'sha256//' . $pin;
    }

    /**
     * @return list<string>
     */
    private static function headerLines(HttpRequest $request): array
    {
        $lines = [];
        foreach ($request->headers as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }
        if ($request->header('Expect') === null) {
            $lines[] = 'Expect:'; // stop curl adding "Expect: 100-continue" on larger POST bodies
        }

        return $lines;
    }
}
