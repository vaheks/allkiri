<?php

declare(strict_types=1);

namespace Allkiri\Http;

/**
 * A service answered with a status the protocol layer cannot interpret.
 * Thrown by protocol clients (OCSP, TSA, ...), never by HttpClient itself.
 */
final class UnexpectedStatusException extends HttpException
{
    public function __construct(
        public readonly int $status,
        public readonly string $body,
        string $message,
    ) {
        parent::__construct($message);
    }

    public static function forResponse(string $what, HttpResponse $response): self
    {
        return new self(
            $response->status,
            $response->body,
            \sprintf('%s answered HTTP %d', $what, $response->status),
        );
    }
}
