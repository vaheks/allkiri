<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Tsp;

use Allkiri\Crypto\Asn1\Asn1Exception;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\NonceGenerator;
use Allkiri\Crypto\RandomNonceGenerator;
use Allkiri\Http\HttpClient;
use Allkiri\Http\HttpRequest;
use Allkiri\Http\TransportException;
use phpseclib3\Math\BigInteger;

/**
 * Obtains RFC 3161 timestamps over HTTP and verifies that the token covers
 * what was sent, before anyone relies on it.
 */
final class TspClient
{
    private const CONTENT_TYPE_QUERY = 'application/timestamp-query';

    public function __construct(
        private readonly HttpClient $http,
        private readonly string $url,
        private readonly TimestampTokenVerifier $verifier = new TimestampTokenVerifier(),
        private readonly NonceGenerator $nonces = new RandomNonceGenerator(),
        private readonly HashAlgorithm $hashAlgorithm = HashAlgorithm::SHA256,
        private readonly ?string $policyOid = null,
    ) {}

    public function url(): string
    {
        return $this->url;
    }

    /**
     * Timestamp the data (hashed here with the configured algorithm).
     *
     * @throws TimestampException
     */
    public function timestamp(string $data): TimestampVerificationResult
    {
        return $this->timestampDigest($this->hashAlgorithm->digest($data));
    }

    /**
     * Timestamp an already computed digest of the configured algorithm.
     *
     * @throws TimestampException
     */
    public function timestampDigest(string $digest): TimestampVerificationResult
    {
        $nonce = new BigInteger("\x01" . $this->nonces->generate(8), 256); // positive, 65 bits, never leading-zero ambiguity
        $request = TimestampRequest::build($this->hashAlgorithm, $digest, $nonce, true, $this->policyOid);

        // Every message that names a URL shows it the way HttpRequest redacts it,
        // which for a TSA changes nothing but keeps one rule for all of them.
        $shown = HttpRequest::withoutIdentities($this->url);
        try {
            $http = $this->http->send(HttpRequest::post($this->url, self::CONTENT_TYPE_QUERY, $request->der, ['Accept' => 'application/timestamp-reply']));
        } catch (TransportException $e) {
            throw new TimestampException('TIMESTAMP_TRANSPORT', \sprintf('Timestamp request to %s failed: %s', $shown, $e->getMessage()), $e);
        }
        if (!$http->isSuccess()) {
            throw new TimestampException('TIMESTAMP_HTTP_STATUS', \sprintf('TSA %s answered HTTP %d', $shown, $http->status));
        }

        try {
            $response = TimestampResponse::fromDer($http->body);
        } catch (Asn1Exception $e) {
            throw new TimestampException('TIMESTAMP_MALFORMED_RESPONSE', \sprintf('TSA %s returned an unparseable response: %s', $shown, $e->getMessage()), $e);
        }
        if (!$response->status()->isGranted()) {
            throw new TimestampException('TIMESTAMP_REJECTED', \sprintf('TSA %s rejected the request (%s%s)', $shown, $response->status()->name, $response->statusText() === [] ? '' : ': ' . implode('; ', $response->statusText())));
        }
        $token = $response->token() ?? throw new TimestampException('TIMESTAMP_MALFORMED_RESPONSE', \sprintf('TSA %s granted the request but sent no token', $shown));

        return $this->verifier->verify($token, $this->hashAlgorithm, $digest, $nonce);
    }
}
