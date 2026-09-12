<?php

declare(strict_types=1);

namespace Allkiri\Http;

use Allkiri\Exception\InvalidArgumentException;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

/**
 * Wraps another client and logs every request it makes.
 *
 * One of these around the client you give to {@see \Allkiri\Allkiri} records
 * every remote call the library performs: Mobile-ID, Smart-ID, timestamps,
 * revocation checks and trusted lists all go through the same interface.
 *
 * ```php
 * $http = new LoggingHttpClient(new CurlHttpClient(), $logger);
 * $allkiri = new Allkiri(Environment::production(), $http, logger: $logger);
 * ```
 *
 * Two things are logged differently from everything else, because getting them
 * wrong is expensive rather than merely untidy.
 *
 * **Credentials are never logged, at any setting.** The Mobile-ID and Smart-ID
 * relying-party identifiers are shared secrets, and a Smart-ID session secret
 * mints device links that the app will accept for the life of that session.
 * Those are replaced wherever they appear.
 *
 * **Personal data is logged only when asked for.** By default bodies are not
 * logged at all, and identity codes are removed from the few URLs that carry
 * them, so the log is a record of calls rather than of people. Pass
 * `personalData: true` while debugging, and know that the log then holds
 * identity codes, phone numbers and certificates, with whatever retention and
 * access rules that implies.
 *
 * An audit trail of who signed what belongs a layer above this: the library's
 * two-step API makes every stage an explicit call in the application, which is
 * where the identity and the business meaning are. See docs/logging.md.
 */
final class LoggingHttpClient implements HttpClient
{
    public const REDACTED = '[redacted]';

    /**
     * Keys whose values are credentials. Matched case-insensitively, at any
     * depth, and never logged whatever else is switched on.
     */
    private const SECRET_KEYS = [
        'relyingpartyuuid',
        'sessionsecret',
    ];

    public function __construct(
        private readonly HttpClient $inner,
        private readonly LoggerInterface $logger,
        private readonly bool $personalData = false,
        private readonly int $maxBodyBytes = 2048,
        private readonly string $level = LogLevel::INFO,
    ) {
        if ($maxBodyBytes < 1) {
            throw new InvalidArgumentException('The body limit must be at least one byte');
        }
    }

    public function send(HttpRequest $request): HttpResponse
    {
        $url = $this->personalData ? $request->url : self::withoutIdentities($request->url);
        $startedAt = microtime(true);

        try {
            $response = $this->inner->send($request);
        } catch (\Throwable $error) {
            // The most interesting line in any of these logs: the call that
            // never came back. Logged, then left exactly as it was thrown.
            $this->logger->warning('{method} {url} failed after {ms} ms: {error}', [
                'method' => $request->method,
                'url' => $url,
                'ms' => self::elapsedMs($startedAt),
                'error' => $error->getMessage(),
                'exception' => $error,
            ]);

            throw $error;
        }

        $context = [
            'method' => $request->method,
            'url' => $url,
            'status' => $response->status,
            'ms' => self::elapsedMs($startedAt),
            'requestBytes' => \strlen($request->body),
            'responseBytes' => \strlen($response->body),
        ];
        if ($this->personalData) {
            $context['requestBody'] = $this->body($request->body, $request->header('Content-Type'));
            $context['responseBody'] = $this->body($response->body, $response->header('Content-Type'));
        }

        $this->logger->log($this->level, '{method} {url} -> {status} in {ms} ms', $context);

        return $response;
    }

    /**
     * A body as it should appear in a log: secrets gone, length bounded, and
     * anything that is not text described rather than printed.
     */
    private function body(string $body, ?string $contentType): string
    {
        if ($body === '') {
            return '';
        }
        if (!self::isText($body)) {
            return \sprintf('<%d bytes of %s>', \strlen($body), $contentType ?? 'unknown type');
        }

        $body = self::redact($body);
        if (\strlen($body) <= $this->maxBodyBytes) {
            return $body;
        }

        // mb_strcut rather than substr: a body cut through the middle of a
        // multi-byte character is invalid UTF-8, which some log backends refuse.
        return mb_strcut($body, 0, $this->maxBodyBytes, 'UTF-8') . \sprintf('… (%d bytes total)', \strlen($body));
    }

    /**
     * Replace credential values in a JSON body, leaving everything else alone.
     *
     * A body that is not JSON is returned unchanged: these services speak JSON,
     * and guessing at the structure of anything else would be more likely to
     * mangle a log line than to protect anything.
     */
    public static function redact(string $body): string
    {
        $decoded = json_decode($body, true);
        if (!\is_array($decoded)) {
            return $body;
        }
        $redacted = json_encode(self::redactValue($decoded), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        return $redacted === false ? self::REDACTED : $redacted;
    }

    /**
     * Remove the identity codes that some Smart-ID paths carry.
     *
     * `/v3/signature/certificate/PNOEE-50001029996-MOCK-Q` names a person and a
     * device. The scheme and country are kept, because they say which service
     * was called without saying who was called about.
     */
    public static function withoutIdentities(string $url): string
    {
        $parts = explode('/', $url);
        foreach ($parts as $index => $part) {
            // ETSI EN 319 412-1 semantics identifiers and SK document numbers:
            // three letters, a country, then the person.
            if (preg_match('/^([A-Z]{3}[A-Z]{2})-.+$/', $part, $matches) === 1) {
                $parts[$index] = $matches[1] . '-' . self::REDACTED;

                continue;
            }
            // A bare national identity number, which older interfaces take.
            if (preg_match('/^\d{11}$/', $part) === 1) {
                $parts[$index] = self::REDACTED;
            }
        }

        return implode('/', $parts);
    }

    private static function redactValue(mixed $value): mixed
    {
        if (!\is_array($value)) {
            return $value;
        }
        $result = [];
        foreach ($value as $key => $item) {
            $result[$key] = \is_string($key) && \in_array(strtolower($key), self::SECRET_KEYS, true)
                ? self::REDACTED
                : self::redactValue($item);
        }

        return $result;
    }

    /**
     * Timestamp tokens and OCSP responses are DER, and trusted lists are large.
     * Neither belongs in a log line as content.
     */
    private static function isText(string $body): bool
    {
        return !str_contains($body, "\0") && mb_check_encoding($body, 'UTF-8');
    }

    private static function elapsedMs(float $startedAt): int
    {
        return (int) round((microtime(true) - $startedAt) * 1000);
    }
}
