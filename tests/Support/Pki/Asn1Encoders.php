<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Pki;

use Allkiri\Crypto\Asn1\Asn1;
use Allkiri\Crypto\Asn1\Maps\CmsMaps;
use Allkiri\Crypto\Asn1\Oids;
use Allkiri\Crypto\EcdsaSignature;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\KeyPair;
use Allkiri\Crypto\KeyType;
use Allkiri\Crypto\SignatureAlgorithm;
use phpseclib3\File\ASN1 as PhpseclibAsn1;

/**
 * Response-side ASN.1 encoders that only tests need (real code only parses
 * these structures). Used by the mock TSA and mock OCSP responder.
 */
final class Asn1Encoders
{
    private function __construct() {}

    /**
     * A CMS SignedData ContentInfo over the content, signed by the key pair
     * with SHA-256 and an ESSCertIDv2 attribute.
     *
     * @param string                                          $eContentTypeOid    e.g. Oids::ID_CT_TST_INFO
     * @param bool                                            $includeCertificate whether to ship the signer certificate
     * @param bool                                            $corruptSignature   flip a bit in the signature (negative tests)
     * @param (\Closure(string): array{string, string})|null $sign               signs the attributes in place of the key's usual algorithm, returning the AlgorithmIdentifier DER and the signature
     */
    public static function signedData(KeyPair $signer, string $eContentTypeOid, string $eContent, \DateTimeImmutable $signingTime, bool $includeCertificate = true, bool $corruptSignature = false, ?\Closure $sign = null): string
    {
        $cert = $signer->certificate;
        $essCertId = Asn1::encode(['certs' => [['certHash' => HashAlgorithm::SHA256->digest($cert->der())]]], CmsMaps::SIGNING_CERTIFICATE_V2);
        $signedAttrs = Asn1::set([
            self::attribute(Oids::ID_CONTENT_TYPE, Asn1::primitive(PhpseclibAsn1::TYPE_OBJECT_IDENTIFIER, $eContentTypeOid)),
            self::attribute(Oids::ID_SIGNING_TIME, self::utcTime($signingTime)),
            self::attribute(Oids::ID_MESSAGE_DIGEST, Asn1::primitive(PhpseclibAsn1::TYPE_OCTET_STRING, HashAlgorithm::SHA256->digest($eContent))),
            self::attribute(Oids::ID_AA_SIGNING_CERTIFICATE_V2, $essCertId),
        ]);

        if ($sign !== null) {
            [$signatureAlgorithm, $signature] = $sign($signedAttrs);
        } else {
            $algorithm = $signer->privateKey->keyType() === KeyType::EC ? SignatureAlgorithm::ES256 : SignatureAlgorithm::RS256;
            $signature = $signer->privateKey->sign($algorithm, $signedAttrs);
            if ($algorithm->keyType() === KeyType::EC) {
                $signature = EcdsaSignature::rawToDer($signature);
            }
            $signatureAlgorithm = self::algorithmIdentifier($algorithm->oid() ?? throw new \LogicException('algorithm without OID'), $algorithm->keyType() === KeyType::RSA);
        }
        if ($corruptSignature) {
            $middle = intdiv(\strlen($signature), 2);
            $signature[$middle] = \chr(\ord($signature[$middle]) ^ 0x01);
        }

        $signerInfo = Asn1::sequence([
            Asn1::integer(1),
            Asn1::sequence([$cert->issuerNameDer(), Asn1::integer($cert->serialNumber())]),
            self::algorithmIdentifier(Oids::SHA256),
            Asn1::implicit(0, $signedAttrs),
            $signatureAlgorithm,
            Asn1::primitive(PhpseclibAsn1::TYPE_OCTET_STRING, $signature),
        ]);

        $parts = [
            Asn1::integer(3),
            Asn1::set([self::algorithmIdentifier(Oids::SHA256)]),
            Asn1::sequence([
                Asn1::primitive(PhpseclibAsn1::TYPE_OBJECT_IDENTIFIER, $eContentTypeOid),
                Asn1::explicit(0, Asn1::primitive(PhpseclibAsn1::TYPE_OCTET_STRING, $eContent)),
            ]),
        ];
        if ($includeCertificate) {
            $parts[] = Asn1::implicit(0, Asn1::set([$cert->der()]));
        }
        $parts[] = Asn1::set([$signerInfo]);

        return Asn1::sequence([
            Asn1::primitive(PhpseclibAsn1::TYPE_OBJECT_IDENTIFIER, Oids::ID_SIGNED_DATA),
            Asn1::explicit(0, Asn1::sequence($parts)),
        ]);
    }

    /**
     * AlgorithmIdentifier { oid, NULL? } — RSA algorithms carry an explicit NULL parameter, EC ones none.
     */
    public static function algorithmIdentifier(string $oid, bool $nullParameters = false): string
    {
        $parts = [Asn1::primitive(PhpseclibAsn1::TYPE_OBJECT_IDENTIFIER, $oid)];
        if ($nullParameters) {
            $parts[] = "\x05\x00";
        }

        return Asn1::sequence($parts);
    }

    public static function attribute(string $oid, string $valueDer): string
    {
        return Asn1::sequence([Asn1::primitive(PhpseclibAsn1::TYPE_OBJECT_IDENTIFIER, $oid), Asn1::set([$valueDer])]);
    }

    public static function generalizedTime(\DateTimeImmutable $time): string
    {
        return self::time($time, PhpseclibAsn1::TYPE_GENERALIZED_TIME);
    }

    public static function utcTime(\DateTimeImmutable $time): string
    {
        return self::time($time, PhpseclibAsn1::TYPE_UTC_TIME);
    }

    private static function time(\DateTimeImmutable $time, int $type): string
    {
        $wrapped = Asn1::encode(
            ['t' => $time->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s')],
            ['type' => PhpseclibAsn1::TYPE_SEQUENCE, 'children' => ['t' => ['type' => $type]]],
        );

        return Asn1::decodeRaw($wrapped)->child(0)->der();
    }
}
