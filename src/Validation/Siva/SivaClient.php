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

    /**
     * @param string $url the validation endpoint: https://, or http:// to this machine only
     */
    public function __construct(
        private readonly HttpClient $http,
        private readonly string $url,
        private readonly string $signaturePolicy = self::POLICY_QES,
    ) {
        // The whole container goes to this URL.
        HttpRequest::requireHttps($url, 'The SiVa URL');
    }

    /**
     * @throws SivaException
     */
    public function validate(string $container, string $filename): SivaReport
    {
        // Often an upload's own name, and it travels as JSON, which cannot carry
        // anything but UTF-8.
        if (!mb_check_encoding($filename, 'UTF-8')) {
            throw new SivaException(SivaException::REASON_REQUEST, 'The file name must be UTF-8 to be sent to SiVa');
        }
        $body = json_encode([
            'document' => base64_encode($container),
            'filename' => $filename,
            'signaturePolicy' => $this->signaturePolicy,
            'reportType' => 'Simple',
        ], JSON_THROW_ON_ERROR);

        try {
            $response = $this->http->send(HttpRequest::post($this->url, 'application/json', $body, ['Accept' => 'application/json']));
        } catch (TransportException $e) {
            throw new SivaException(SivaException::REASON_TRANSPORT, 'Could not reach SiVa at ' . HttpRequest::withoutIdentities($this->url) . ': ' . $e->getMessage(), $e);
        }
        // RIA's SiVa sits behind Cloudflare, which now and then answers a server
        // with a page meant for a browser. Cloudflare marks every such page with
        // this header; the page itself says nothing a caller can use.
        if ($response->header('cf-mitigated') === 'challenge') {
            throw new SivaException(SivaException::REASON_CHALLENGED, \sprintf(
                'SiVa at %s answered HTTP %d with a bot-protection challenge instead of a verdict. Try again later; if every request from this server is refused, RIA has to let it through',
                HttpRequest::withoutIdentities($this->url),
                $response->status,
            ));
        }
        if (!$response->isSuccess()) {
            throw new SivaException(SivaException::REASON_HTTP_STATUS, \sprintf('SiVa answered HTTP %d: %s', $response->status, mb_substr($response->body, 0, 500)));
        }

        $decoded = json_decode($response->body, true);
        if (!\is_array($decoded)) {
            throw new SivaException(SivaException::REASON_MALFORMED, 'SiVa did not answer with JSON');
        }

        return SivaReport::fromArray($decoded);
    }
}
