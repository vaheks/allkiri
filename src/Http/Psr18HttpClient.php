<?php

declare(strict_types=1);

namespace Allkiri\Http;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * Adapts any PSR-18 client (Guzzle, Symfony HttpClient, ...) to {@see HttpClient}.
 *
 * Public-key pinning is the caller's responsibility with this adapter;
 * configure it on the underlying client if the service recommends it.
 */
final class Psr18HttpClient implements HttpClient
{
    public function __construct(
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
    ) {}

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
            throw new TransportException(\sprintf('%s %s failed: %s', $request->method, $request->url, $e->getMessage()), 0, $e);
        }

        $headers = [];
        foreach ($psrResponse->getHeaders() as $name => $values) {
            // PHP turns a purely numeric header name into an int array key; restore the string.
            $headers[(string) $name] = implode(', ', $values);
        }

        return new HttpResponse($psrResponse->getStatusCode(), $headers, (string) $psrResponse->getBody());
    }
}
