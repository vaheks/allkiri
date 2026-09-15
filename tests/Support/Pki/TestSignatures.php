<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Pki;

use Allkiri\Crypto\Phpseclib;
use phpseclib3\Crypt\RSA;

/**
 * Signers for the mock OCSP responder and TSA ({@see MockOcspResponder::$sign},
 * {@see MockTsa::$sign}), for algorithms allkiri's own PrivateKey will not
 * produce.
 */
final class TestSignatures
{
    private function __construct() {}

    /**
     * sha1WithRSAEncryption or ecdsa-with-SHA1, by the key's type.
     *
     * @return \Closure(string): array{string, string} the AlgorithmIdentifier DER, and the signature over the data
     */
    public static function sha1(TestKey $key): \Closure
    {
        return static function (string $data) use ($key): array {
            $raw = $key->raw;
            if ($raw instanceof RSA\PrivateKey) {
                $signer = Phpseclib::rsaPrivate(Phpseclib::rsaPrivate($raw->withPadding(RSA::SIGNATURE_PKCS1))->withHash('sha1'));

                return [Asn1Encoders::algorithmIdentifier('1.2.840.113549.1.1.5', true), Phpseclib::string($signer->sign($data))];
            }
            $signer = Phpseclib::ecPrivate(Phpseclib::ecPrivate($raw->withSignatureFormat('ASN1'))->withHash('sha1'));

            return [Asn1Encoders::algorithmIdentifier('1.2.840.10045.4.1'), Phpseclib::string($signer->sign($data))];
        };
    }
}
