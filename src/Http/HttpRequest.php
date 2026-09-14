<?php

declare(strict_types=1);

namespace Allkiri\Http;

use Allkiri\Exception\InvalidArgumentException;

final readonly class HttpRequest
{
    /** What an identity code in a URL is replaced with wherever the URL is shown. */
    public const REDACTED = '[redacted]';

    /** The only hosts a service URL may reach over plain HTTP. */
    private const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

    /**
     * @param non-empty-string      $method
     * @param non-empty-string      $url
     * @param array<string, string> $headers header names as given by the caller
     */
    private function __construct(
        public string $method,
        public string $url,
        public array $headers,
        public string $body,
    ) {}

    /**
     * @param array<string, string> $headers
     */
    public static function get(string $url, array $headers = []): self
    {
        return new self('GET', self::requireHttpUrl($url), $headers, '');
    }

    /**
     * @param array<string, string> $headers
     */
    public static function post(string $url, string $contentType, string $body, array $headers = []): self
    {
        $headers['Content-Type'] = $contentType;

        return new self('POST', self::requireHttpUrl($url), $headers, $body);
    }

    /**
     * Header value by case-insensitive name, or null when absent.
     */
    public function header(string $name): ?string
    {
        foreach ($this->headers as $key => $value) {
            if (strcasecmp($key, $name) === 0) {
                return $value;
            }
        }

        return null;
    }

    /**
     * The URL as it may appear in a message or a log: without the identity
     * codes some paths carry.
     *
     * Every exception that names a URL uses this, so that neither the
     * library's logs nor an application logging the exception records who was
     * called about.
     */
    public function redactedUrl(): string
    {
        return self::withoutIdentities($this->url);
    }

    /**
     * Remove the identity codes that some Smart-ID paths carry.
     *
     * `/v3/signature/certificate/PNOEE-50001029996-MOCK-Q` names a person and a
     * device. The type and country are kept, because they say which service
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

    /**
     * Refuse a service URL that is not HTTPS.
     *
     * For the services that receive relying-party credentials, identity codes
     * or whole documents: Mobile-ID, Smart-ID and SiVa. Plain HTTP is allowed
     * only to this machine, for a mock service or a tunnel, and a host name
     * that merely begins with "localhost" is not this machine. Timestamp and
     * OCSP URLs are not checked: those services are plain HTTP by design, and
     * what they answer is signed.
     *
     * @param string $what what the URL is for, which the message starts with
     *
     * @throws InvalidArgumentException
     */
    public static function requireHttps(string $url, string $what): void
    {
        $parts = parse_url($url);
        $scheme = \is_array($parts) ? strtolower($parts['scheme'] ?? '') : '';
        $host = \is_array($parts) ? strtolower($parts['host'] ?? '') : '';
        if ($host !== '' && ($scheme === 'https' || ($scheme === 'http' && \in_array($host, self::LOOPBACK_HOSTS, true)))) {
            return;
        }

        throw new InvalidArgumentException(\sprintf(
            '%s must be an https:// URL, or http:// to localhost, 127.0.0.1 or [::1], not "%s"',
            $what,
            self::withoutIdentities($url),
        ));
    }

    /**
     * @return non-empty-string
     */
    private static function requireHttpUrl(string $url): string
    {
        $scheme = parse_url($url, PHP_URL_SCHEME);
        if ($url === '' || !\is_string($scheme) || !\in_array(strtolower($scheme), ['http', 'https'], true)) {
            throw new InvalidArgumentException(\sprintf('Expected an http(s) URL, got "%s"', $url));
        }

        return $url;
    }
}
