<?php

declare(strict_types=1);

namespace Allkiri\Http;

/**
 * The one HTTP abstraction every remote call in allkiri goes through
 * (OCSP, TSA, trusted lists, Mobile-ID, Smart-ID, SiVa).
 *
 * Deliberately smaller than PSR-18 so that no PSR-7 implementation is
 * required; {@see Psr18HttpClient} adapts any PSR-18 client and
 * {@see CurlHttpClient} is the default with TLS public-key pinning.
 */
interface HttpClient
{
    /**
     * The largest answer the built-in clients accept unless told otherwise.
     *
     * 16 MiB is three times the largest national trusted list the European list
     * of lists linked to in September 2026 (Germany's, 5.4 MB). Everything else
     * allkiri fetches is measured in kilobytes.
     */
    public const DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

    /**
     * Send the request and return whatever the server answered.
     *
     * Non-2xx statuses are returned, not thrown; callers decide what a
     * failure means for their protocol.
     *
     * @throws TransportException when no usable HTTP response could be obtained
     *                            (DNS, connection, TLS, timeout, pinning, or an
     *                            answer larger than the client accepts)
     */
    public function send(HttpRequest $request): HttpResponse;
}
