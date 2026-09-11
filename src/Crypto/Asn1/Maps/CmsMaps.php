<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Asn1\Maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;

/**
 * RFC 5652 CMS SignedData (as used by RFC 3161 tokens) and RFC 5035 ESS
 * signing-certificate attributes. Certificates and attribute values are ANY so
 * that their DER is sliced from the original bytes, never re-encoded.
 */
final class CmsMaps
{
    public const CONTENT_INFO = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'contentType' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
        'content' => ['type' => ASN1::TYPE_ANY, 'constant' => 0, 'explicit' => true, 'optional' => true],
    ]];

    public const ATTRIBUTE = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'type' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
        'values' => ['type' => ASN1::TYPE_SET, 'min' => 1, 'max' => -1, 'children' => ['type' => ASN1::TYPE_ANY]],
    ]];

    public const ISSUER_AND_SERIAL_NUMBER = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'issuer' => Maps\Name::MAP,
        'serialNumber' => Maps\CertificateSerialNumber::MAP,
    ]];

    public const SIGNER_IDENTIFIER = ['type' => ASN1::TYPE_CHOICE, 'children' => [
        'issuerAndSerialNumber' => self::ISSUER_AND_SERIAL_NUMBER,
        'subjectKeyIdentifier' => ['type' => ASN1::TYPE_OCTET_STRING, 'constant' => 0, 'implicit' => true],
    ]];

    public const SIGNER_INFO = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'version' => ['type' => ASN1::TYPE_INTEGER],
        'sid' => self::SIGNER_IDENTIFIER,
        'digestAlgorithm' => Maps\AlgorithmIdentifier::MAP,
        'signedAttrs' => ['type' => ASN1::TYPE_SET, 'constant' => 0, 'implicit' => true, 'optional' => true, 'min' => 1, 'max' => -1, 'children' => self::ATTRIBUTE],
        'signatureAlgorithm' => Maps\AlgorithmIdentifier::MAP,
        'signature' => ['type' => ASN1::TYPE_OCTET_STRING],
        'unsignedAttrs' => ['type' => ASN1::TYPE_SET, 'constant' => 1, 'implicit' => true, 'optional' => true, 'min' => 1, 'max' => -1, 'children' => self::ATTRIBUTE],
    ]];

    public const ENCAPSULATED_CONTENT_INFO = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'eContentType' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
        'eContent' => ['type' => ASN1::TYPE_OCTET_STRING, 'constant' => 0, 'explicit' => true, 'optional' => true],
    ]];

    public const SIGNED_DATA = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'version' => ['type' => ASN1::TYPE_INTEGER],
        'digestAlgorithms' => ['type' => ASN1::TYPE_SET, 'min' => 0, 'max' => -1, 'children' => Maps\AlgorithmIdentifier::MAP],
        'encapContentInfo' => self::ENCAPSULATED_CONTENT_INFO,
        'certificates' => ['type' => ASN1::TYPE_SET, 'constant' => 0, 'implicit' => true, 'optional' => true, 'min' => 0, 'max' => -1, 'children' => ['type' => ASN1::TYPE_ANY]],
        'crls' => ['type' => ASN1::TYPE_SET, 'constant' => 1, 'implicit' => true, 'optional' => true, 'min' => 0, 'max' => -1, 'children' => ['type' => ASN1::TYPE_ANY]],
        'signerInfos' => ['type' => ASN1::TYPE_SET, 'min' => 0, 'max' => -1, 'children' => self::SIGNER_INFO],
    ]];

    public const ISSUER_SERIAL = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'issuer' => Maps\GeneralNames::MAP,
        'serialNumber' => Maps\CertificateSerialNumber::MAP,
    ]];

    public const ESS_CERT_ID_V2 = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'hashAlgorithm' => Maps\AlgorithmIdentifier::MAP + ['optional' => true],
        'certHash' => ['type' => ASN1::TYPE_OCTET_STRING],
        'issuerSerial' => self::ISSUER_SERIAL + ['optional' => true],
    ]];

    public const SIGNING_CERTIFICATE_V2 = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'certs' => ['type' => ASN1::TYPE_SEQUENCE, 'min' => 1, 'max' => -1, 'children' => self::ESS_CERT_ID_V2],
        'policies' => ['type' => ASN1::TYPE_SEQUENCE, 'optional' => true, 'min' => 0, 'max' => -1, 'children' => ['type' => ASN1::TYPE_ANY]],
    ]];

    /** RFC 2634 ESSCertID: always SHA-1, only accepted on parse. */
    public const ESS_CERT_ID = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'certHash' => ['type' => ASN1::TYPE_OCTET_STRING],
        'issuerSerial' => self::ISSUER_SERIAL + ['optional' => true],
    ]];

    public const SIGNING_CERTIFICATE = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'certs' => ['type' => ASN1::TYPE_SEQUENCE, 'min' => 1, 'max' => -1, 'children' => self::ESS_CERT_ID],
        'policies' => ['type' => ASN1::TYPE_SEQUENCE, 'optional' => true, 'min' => 0, 'max' => -1, 'children' => ['type' => ASN1::TYPE_ANY]],
    ]];

    private function __construct() {}
}
