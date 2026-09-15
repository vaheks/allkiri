<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Ocsp;

use Allkiri\Crypto\Asn1\Asn1;
use Allkiri\Crypto\Asn1\Asn1Exception;
use Allkiri\Crypto\Asn1\Maps\OcspMaps;
use Allkiri\Crypto\Asn1\Oids;
use phpseclib3\File\ASN1 as PhpseclibAsn1;

/**
 * An unsigned OCSPRequest for one certificate, optionally with a nonce
 * (RFC 8954: the extension value is an OCTET STRING wrapping the nonce bytes).
 *
 * @internal
 */
final readonly class OcspRequest
{
    private function __construct(
        public CertId $certId,
        public ?string $nonce,
        public string $der,
    ) {}

    public static function build(CertId $certId, ?string $nonce = null): self
    {
        $tbs = ['requestList' => [['reqCert' => $certId->toMapped()]]];
        if ($nonce !== null) {
            $tbs['requestExtensions'] = [[
                'extnId' => 'id-pkix-ocsp-nonce',
                'critical' => false,
                'extnValue' => Asn1::primitive(PhpseclibAsn1::TYPE_OCTET_STRING, $nonce),
            ]];
        }

        return new self($certId, $nonce, Asn1::encode(['tbsRequest' => $tbs], OcspMaps::OCSP_REQUEST));
    }

    /**
     * Parse a request as received by a responder (used by the test responder).
     */
    public static function fromDer(string $der): self
    {
        $decoded = Asn1::decode($der, OcspMaps::OCSP_REQUEST);
        $requests = $decoded->array('tbsRequest', 'requestList');
        $first = $requests[0] ?? null;
        if (!\is_array($first) || !\is_array($first['reqCert'] ?? null)) {
            throw new Asn1Exception('OCSPRequest has no request');
        }
        $nonce = null;
        $extensions = $decoded->get('tbsRequest', 'requestExtensions');
        if (\is_array($extensions)) {
            $nonce = self::nonceFromExtensions($extensions);
        }

        return new self(CertId::fromMapped($first['reqCert']), $nonce, $der);
    }

    /**
     * The nonce bytes from a decoded Extensions list, unwrapping the inner
     * OCTET STRING when present (RFC 8954) and tolerating raw bytes (older responders).
     *
     * @param array<mixed> $extensions
     */
    public static function nonceFromExtensions(array $extensions): ?string
    {
        foreach ($extensions as $extension) {
            if (!\is_array($extension)) {
                continue;
            }
            $id = $extension['extnId'] ?? null;
            if (!\is_string($id) || Oids::dotted($id) !== Oids::ID_PKIX_OCSP_NONCE) {
                continue;
            }
            $value = $extension['extnValue'] ?? null;
            if (!\is_string($value)) {
                return null;
            }
            if ($value !== '' && $value[0] === "\x04") {
                try {
                    $inner = Asn1::decodeRaw($value);
                    if (!$inner->isTagged() && $inner->type() === PhpseclibAsn1::TYPE_OCTET_STRING) {
                        return $inner->string();
                    }
                } catch (Asn1Exception) {
                    // raw nonce bytes that merely start with 0x04
                }
            }

            return $value;
        }

        return null;
    }
}
