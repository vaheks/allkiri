<?php

declare(strict_types=1);

namespace Allkiri\Http;

final readonly class HttpResponse
{
    /** @var array<string, string> header names lower-cased, repeated headers joined with ", " */
    public array $headers;

    /**
     * @param array<string, string> $headers any casing; normalised here
     */
    public function __construct(
        public int $status,
        array $headers,
        public string $body,
    ) {
        $normalised = [];
        foreach ($headers as $name => $value) {
            $normalised[strtolower($name)] = $value;
        }
        $this->headers = $normalised;
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    /**
     * The media type without parameters, lower-cased: "application/ocsp-response".
     */
    public function contentType(): ?string
    {
        $raw = $this->header('Content-Type');
        if ($raw === null) {
            return null;
        }
        $type = explode(';', $raw, 2)[0];

        return strtolower(trim($type));
    }

    public function isSuccess(): bool
    {
        return $this->status >= 200 && $this->status < 300;
    }
}
