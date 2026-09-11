<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Tsp;

use Allkiri\Crypto\Asn1\Asn1;
use Allkiri\Crypto\Asn1\Maps\TspMaps;
use Allkiri\Crypto\Asn1\Oids;
use phpseclib3\Math\BigInteger;

/**
 * TSTInfo (RFC 3161 §2.4.2): what the TSA asserts.
 */
final readonly class TstInfo
{
    private function __construct(
        public string $policyOid,
        public string $hashAlgorithmOid,
        public string $messageImprint,
        public string $serialNumber,
        public \DateTimeImmutable $genTime,
        public ?BigInteger $nonce,
        public ?int $accuracySeconds,
        public string $der,
    ) {}

    public static function fromDer(string $der): self
    {
        $decoded = Asn1::decode($der, TspMaps::TST_INFO);
        $serial = $decoded->get('serialNumber');
        $nonce = $decoded->get('nonce');
        $accuracy = $decoded->get('accuracy', 'seconds');

        return new self(
            Oids::dotted($decoded->string('policy')),
            Oids::dotted($decoded->string('messageImprint', 'hashAlgorithm', 'algorithm')),
            $decoded->string('messageImprint', 'hashedMessage'),
            $serial instanceof BigInteger ? $serial->toString() : '0',
            $decoded->node()->child(4)->time(),
            $nonce instanceof BigInteger ? $nonce : null,
            $accuracy instanceof BigInteger ? (int) $accuracy->toString() : null,
            $der,
        );
    }
}
