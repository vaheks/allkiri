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
     * Send the request and return whatever the server answered.
     *
     * Non-2xx statuses are returned, not thrown; callers decide what a
     * failure means for their protocol.
     *
     * @throws TransportException when no HTTP response could be obtained
     *                            (DNS, connection, TLS, timeout, pinning)
     */
    public function send(HttpRequest $request): HttpResponse;
}
