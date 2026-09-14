<?php

declare(strict_types=1);

namespace Allkiri\Http;

use Allkiri\Exception\InvalidArgumentException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;

/**
 * Adapts any PSR-18 client (Guzzle, Symfony HttpClient, ...) to {@see HttpClient}.
 *
 * Public-key pinning is the caller's responsibility with this adapter;
 * configure it on the underlying client if the service recommends it.
 *
 * An answer larger than `$maxResponseBytes` is refused. That bounds the copy
 * this adapter makes, not what the PSR-18 client may already have buffered
 * before handing the response over; limit that on the client itself.
 */
final class Psr18HttpClient implements HttpClient
{
    private const CHUNK_BYTES = 65_536;

    public function __construct(
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly int $maxResponseBytes = HttpClient::DEFAULT_MAX_RESPONSE_BYTES,
    ) {
        if ($maxResponseBytes < 1) {
            throw new InvalidArgumentException('The response limit must be at least one byte');
        }
    }

    public function send(HttpRequest $request): HttpResponse
    {
        $psrRequest = $this->requestFactory->createRequest($request->method, $request->url);
        foreach ($request->headers as $name => $value) {
            $psrRequest = $psrRequest->withHeader($name, $value);
        }
        if ($request->body !== '') {
            $psrRequest = $psrRequest->withBody($this->streamFactory->createStream($request->body));
        }

        try {
            $psrResponse = $this->client->sendRequest($psrRequest);
        } catch (ClientExceptionInterface $e) {
            throw new TransportException(\sprintf('%s %s failed: %s', $request->method, $request->redactedUrl(), self::described($e, $request, $psrRequest)));
        }

        $headers = [];
        foreach ($psrResponse->getHeaders() as $name => $values) {
            // PHP turns a purely numeric header name into an int array key; restore the string.
            $headers[(string) $name] = implode(', ', $values);
        }

        return new HttpResponse($psrResponse->getStatusCode(), $headers, $this->body($psrResponse->getBody(), $request, $psrRequest));
    }

    /**
     * The body, read in pieces so that no more than the limit is ever held.
     */
    private function body(StreamInterface $stream, HttpRequest $request, RequestInterface $psrRequest): string
    {
        // A stream that knows its size is refused before any of it is read.
        $size = $stream->getSize();
        if ($size !== null && $size > $this->maxResponseBytes) {
            throw TransportException::responseTooLarge($request, $this->maxResponseBytes);
        }

        $body = new BoundedBody($this->maxResponseBytes);
        try {
            if ($stream->isSeekable()) {
                $stream->rewind();
            }
            while (!$stream->eof() && $body->append($stream->read(self::CHUNK_BYTES))) {
                // append() stops the loop at the limit
            }
        } catch (\RuntimeException $e) {
            // PSR-7 streams throw this when the connection fails mid-body.
            throw new TransportException(\sprintf('%s %s: the answer could not be read: %s', $request->method, $request->redactedUrl(), self::described($e, $request, $psrRequest)));
        }
        if ($body->exceeded()) {
            throw TransportException::responseTooLarge($request, $this->maxResponseBytes);
        }

        return $body->bytes();
    }

    /**
     * Another library's exception, as a message allkiri can carry.
     *
     * Guzzle and Symfony put the whole URL, identity codes included, into their
     * own messages, and most loggers print a chained exception as well. So the
     * URL is scrubbed from the message, and the original is named rather than
     * chained.
     */
    private static function described(\Throwable $e, HttpRequest $request, RequestInterface $psrRequest): string
    {
        return \sprintf(
            '%s (%s)',
            str_replace([$request->url, (string) $psrRequest->getUri()], $request->redactedUrl(), $e->getMessage()),
            get_debug_type($e),
        );
    }
}
