<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Tsp;

use Allkiri\Crypto\Asn1\Asn1;
use Allkiri\Crypto\Asn1\Asn1Exception;
use Allkiri\Crypto\Asn1\Maps\TspMaps;
use Allkiri\Crypto\Asn1\Oids;
use Allkiri\Crypto\HashAlgorithm;
use phpseclib3\Math\BigInteger;

/**
 * An RFC 3161 TimeStampReq.
 */
final readonly class TimestampRequest
{
    private function __construct(
        public HashAlgorithm $hashAlgorithm,
        public string $imprint,
        public ?BigInteger $nonce,
        public bool $certReq,
        public ?string $policyOid,
        public string $der,
    ) {}

    public static function build(HashAlgorithm $hashAlgorithm, string $imprint, ?BigInteger $nonce = null, bool $certReq = true, ?string $policyOid = null): self
    {
        if (\strlen($imprint) !== $hashAlgorithm->digestLength()) {
            throw new Asn1Exception(\sprintf('Imprint must be %d bytes for %s', $hashAlgorithm->digestLength(), $hashAlgorithm->name()));
        }
        $value = [
            'version' => new BigInteger(1),
            'messageImprint' => ['hashAlgorithm' => ['algorithm' => $hashAlgorithm->oid()], 'hashedMessage' => $imprint],
        ];
        if ($policyOid !== null) {
            $value['reqPolicy'] = $policyOid;
        }
        if ($nonce !== null) {
            $value['nonce'] = $nonce;
        }
        if ($certReq) {
            $value['certReq'] = true;
        }

        return new self($hashAlgorithm, $imprint, $nonce, $certReq, $policyOid, Asn1::encode($value, TspMaps::TIME_STAMP_REQ));
    }

    /**
     * Parse a request as received by a TSA (used by the test TSA).
     */
    public static function fromDer(string $der): self
    {
        $decoded = Asn1::decode($der, TspMaps::TIME_STAMP_REQ);
        $hash = HashAlgorithm::fromOid(Oids::dotted($decoded->string('messageImprint', 'hashAlgorithm', 'algorithm')));
        $nonce = $decoded->get('nonce');
        $certReq = $decoded->get('certReq');
        $policy = $decoded->get('reqPolicy');

        return new self(
            $hash,
            $decoded->string('messageImprint', 'hashedMessage'),
            $nonce instanceof BigInteger ? $nonce : null,
            $certReq === true,
            \is_string($policy) ? Oids::dotted($policy) : null,
            $der,
        );
    }
}
