<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Ocsp;

use Allkiri\Crypto\Asn1\Asn1;
use Allkiri\Crypto\Asn1\Asn1Exception;
use Allkiri\Crypto\Asn1\Maps\OcspMaps;
use Allkiri\Crypto\Asn1\Oids;

/**
 * The outer OCSPResponse: status plus, when successful, the basic response.
 * The original DER is what gets embedded into a XAdES RevocationValues.
 */
final class OcspResponse
{
    private readonly OcspResponseStatus $status;

    private readonly ?BasicOcspResponse $basic;

    private function __construct(private readonly string $der)
    {
        $decoded = Asn1::decode($der, OcspMaps::OCSP_RESPONSE);
        $status = OcspResponseStatus::tryFrom($decoded->string('responseStatus')) ?? throw new Asn1Exception('Unknown OCSP response status');
        $this->status = $status;
        $basic = null;
        if ($status === OcspResponseStatus::Successful && $decoded->has('responseBytes')) {
            if (Oids::dotted($decoded->string('responseBytes', 'responseType')) === Oids::ID_PKIX_OCSP_BASIC) {
                $basic = BasicOcspResponse::fromDer($decoded->string('responseBytes', 'response'));
            }
        }
        $this->basic = $basic;
    }

    public static function fromDer(string $der): self
    {
        return new self($der);
    }

    public function der(): string
    {
        return $this->der;
    }

    public function status(): OcspResponseStatus
    {
        return $this->status;
    }

    /**
     * The basic response, or null when the status is not successful or the
     * response type is something other than id-pkix-ocsp-basic.
     */
    public function basic(): ?BasicOcspResponse
    {
        return $this->basic;
    }
}
