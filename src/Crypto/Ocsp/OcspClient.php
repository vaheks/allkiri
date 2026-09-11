<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Ocsp;

use Allkiri\Crypto\Asn1\Asn1Exception;
use Allkiri\Crypto\Asn1\Oids;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\NonceGenerator;
use Allkiri\Crypto\RandomNonceGenerator;
use Allkiri\Http\HttpClient;
use Allkiri\Http\HttpRequest;
use Allkiri\Http\TransportException;
use Psr\Clock\ClockInterface;

/**
 * Asks a responder whether a certificate is good right now.
 *
 * Responder URL: an override for the issuer, else the certificate's own AIA
 * entry, else the configured default. Overrides exist for contract
 * endpoints (ocsp.sk.ee) and for certificates without AIA.
 */
final class OcspClient
{
    public const NONCE_BYTES = 32;

    private const CONTENT_TYPE_REQUEST = 'application/ocsp-request';

    /**
     * @param array<string, string> $urlOverrides issuer subject DN (as {@see Certificate::subjectDn()}) => responder URL
     * @param string|null           $defaultUrl   used when neither an override nor an AIA entry exists
     */
    public function __construct(
        private readonly HttpClient $http,
        private readonly ClockInterface $clock,
        private readonly OcspResponseVerifier $verifier = new OcspResponseVerifier(),
        private readonly NonceGenerator $nonces = new RandomNonceGenerator(),
        private readonly OcspVerificationOptions $options = new OcspVerificationOptions(),
        private readonly array $urlOverrides = [],
        private readonly ?string $defaultUrl = null,
        private readonly string $certIdHashOid = Oids::SHA1,
    ) {}

    /**
     * Fetch and verify a fresh answer; only a verified `good` returns.
     *
     * @param list<Certificate> $trustedResponders trusted-list OCSP anchors for this CA, if any
     *
     * @throws OcspException                for transport, protocol and verification failures
     * @throws CertificateRevokedException  when the verified status is revoked or unknown
     */
    public function fetch(Certificate $subject, Certificate $issuer, array $trustedResponders = []): OcspResult
    {
        $url = $this->responderUrl($subject, $issuer);
        $nonce = $this->options->nonceMode === NonceMode::Ignore ? null : $this->nonces->generate(self::NONCE_BYTES);
        $request = OcspRequest::build(CertId::for($subject, $issuer, $this->certIdHashOid), $nonce);

        try {
            $http = $this->http->send(HttpRequest::post($url, self::CONTENT_TYPE_REQUEST, $request->der, ['Accept' => 'application/ocsp-response']));
        } catch (TransportException $e) {
            throw new OcspException('OCSP_TRANSPORT', \sprintf('OCSP request to %s failed: %s', $url, $e->getMessage()), $e);
        }
        if (!$http->isSuccess()) {
            throw new OcspException('OCSP_HTTP_STATUS', \sprintf('OCSP responder %s answered HTTP %d', $url, $http->status));
        }

        try {
            $response = OcspResponse::fromDer($http->body);
        } catch (Asn1Exception $e) {
            throw new OcspException('OCSP_MALFORMED_RESPONSE', \sprintf('OCSP responder %s returned an unparseable response: %s', $url, $e->getMessage()), $e);
        }

        $options = $trustedResponders === [] ? $this->options : $this->options->withTrustedResponders($trustedResponders);
        $verification = $this->verifier->verify($response, $subject, $issuer, $nonce, $this->clock->now(), $options);

        switch ($verification->status()) {
            case CertStatus::Good:
                return new OcspResult($url, $response, $verification);
            case CertStatus::Revoked:
                throw new CertificateRevokedException(
                    CertificateRevokedException::REASON_REVOKED,
                    \sprintf('Certificate %s is revoked', $subject->subjectDn()),
                    $verification->single->revokedAt,
                    $verification->single->revocationReason,
                );
            case CertStatus::Unknown:
                throw new CertificateRevokedException(CertificateRevokedException::REASON_UNKNOWN, \sprintf('OCSP responder %s does not know certificate %s', $url, $subject->subjectDn()));
        }
    }

    public function responderUrl(Certificate $subject, Certificate $issuer): string
    {
        $override = $this->urlOverrides[$issuer->subjectDn()] ?? null;
        if ($override !== null) {
            return $override;
        }
        $aia = $subject->ocspUrls();
        if ($aia !== []) {
            return $aia[0];
        }

        return $this->defaultUrl ?? throw new OcspException('OCSP_NO_RESPONDER_URL', \sprintf('No OCSP responder known for certificates issued by %s', $issuer->subjectDn()));
    }
}
