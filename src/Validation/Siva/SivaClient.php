<?php

declare(strict_types=1);

namespace Allkiri\Validation\Siva;

use Allkiri\Http\HttpClient;
use Allkiri\Http\HttpRequest;
use Allkiri\Http\TransportException;

/**
 * RIA's signature validation service, as a second opinion.
 *
 * allkiri validates natively; this is for comparing that verdict with the
 * state's, and for the formats allkiri does not read (DDOC, signed PDF).
 * The whole container is sent, so do not point it at a service you would not
 * show the document to.
 */
final class SivaClient
{
    public const POLICY_QES = 'POLv4';
    public const POLICY_ADES = 'POLv3';

    public function __construct(
        private readonly HttpClient $http,
        private readonly string $url,
        private readonly string $signaturePolicy = self::POLICY_QES,
    ) {}

    /**
     * @throws SivaException
     */
    public function validate(string $container, string $filename): SivaReport
    {
        $body = json_encode([
            'document' => base64_encode($container),
            'filename' => $filename,
            'signaturePolicy' => $this->signaturePolicy,
            'reportType' => 'Simple',
        ], JSON_THROW_ON_ERROR);

        try {
            $response = $this->http->send(HttpRequest::post($this->url, 'application/json', $body, ['Accept' => 'application/json']));
        } catch (TransportException $e) {
            throw new SivaException('Could not reach SiVa at ' . HttpRequest::withoutIdentities($this->url) . ': ' . $e->getMessage(), 0, $e);
        }
        if (!$response->isSuccess()) {
            throw new SivaException(\sprintf('SiVa answered HTTP %d: %s', $response->status, mb_substr($response->body, 0, 500)));
        }

        $decoded = json_decode($response->body, true);
        if (!\is_array($decoded)) {
            throw new SivaException('SiVa did not answer with JSON');
        }

        return SivaReport::fromArray($decoded);
    }
}
