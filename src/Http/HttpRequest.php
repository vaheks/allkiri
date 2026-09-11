<?php

declare(strict_types=1);

namespace Allkiri\Http;

use Allkiri\Exception\InvalidArgumentException;

final readonly class HttpRequest
{
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
