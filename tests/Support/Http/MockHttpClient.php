<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Http;

use Allkiri\Http\HttpClient;
use Allkiri\Http\HttpRequest;
use Allkiri\Http\HttpResponse;
use Allkiri\Http\TransportException;

/**
 * Routes requests by URL prefix to handlers and records everything it saw.
 *
 * The mock OCSP responder and mock TSA register themselves here, so a whole
 * LT signing run can happen offline.
 */
final class MockHttpClient implements HttpClient
{
    /** @var list<array{prefix: string, handler: \Closure(HttpRequest): HttpResponse}> longest prefix wins */
    private array $routes = [];

    /** @var list<HttpRequest> */
    private array $requests = [];

    /**
     * @param \Closure(HttpRequest): HttpResponse $handler
     */
    public function on(string $urlPrefix, \Closure $handler): self
    {
        $this->routes[] = ['prefix' => $urlPrefix, 'handler' => $handler];
        usort($this->routes, static fn(array $a, array $b): int => \strlen($b['prefix']) <=> \strlen($a['prefix']));

        return $this;
    }

    /**
     * Shorthand: always answer a fixed response for the prefix.
     */
    public function respond(string $urlPrefix, int $status, string $contentType, string $body): self
    {
        return $this->on($urlPrefix, static fn(HttpRequest $r): HttpResponse => new HttpResponse($status, ['Content-Type' => $contentType], $body));
    }

    public function send(HttpRequest $request): HttpResponse
    {
        $this->requests[] = $request;
        foreach ($this->routes as $route) {
            if (str_starts_with($request->url, $route['prefix'])) {
                return ($route['handler'])($request);
            }
        }

        throw new TransportException(\sprintf('MockHttpClient has no route for %s %s', $request->method, $request->url));
    }

    /**
     * @return list<HttpRequest>
     */
    public function requests(): array
    {
        return $this->requests;
    }

    public function lastRequest(): ?HttpRequest
    {
        return $this->requests === [] ? null : $this->requests[\count($this->requests) - 1];
    }

    public function requestCount(?string $urlPrefix = null): int
    {
        if ($urlPrefix === null) {
            return \count($this->requests);
        }

        return \count(array_filter($this->requests, static fn(HttpRequest $r): bool => str_starts_with($r->url, $urlPrefix)));
    }
}
