<?php

declare(strict_types=1);

namespace Allkiri\Http;

/**
 * No usable HTTP response was obtained: DNS, connection, TLS handshake, pinning
 * mismatch, timeout, or an answer larger than the client accepts. The message
 * carries the transport's own wording, with identity codes removed from the URL.
 */
final class TransportException extends HttpException
{
    /**
     * The answer was larger than the client accepts. It is refused rather than
     * cut short, because part of a trusted list or a container is not a smaller
     * valid one.
     */
    public static function responseTooLarge(HttpRequest $request, int $limit): self
    {
        return new self(\sprintf('%s %s answered with more than the %d bytes this client accepts', $request->method, $request->redactedUrl(), $limit));
    }
}
