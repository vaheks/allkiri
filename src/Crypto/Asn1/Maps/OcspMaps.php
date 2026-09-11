<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Asn1\Maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;

/**
 * RFC 6960 structures. Adapted from the OCSP maps of
 * web-eid/web-eid-authtoken-validation-php (MIT, Estonian Information System
 * Authority) with the responder certificates kept as ANY so their DER can be
 * sliced instead of re-encoded.
 */
final class OcspMaps
{
    public const CERT_ID = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'hashAlgorithm' => Maps\AlgorithmIdentifier::MAP,
        'issuerNameHash' => ['type' => ASN1::TYPE_OCTET_STRING],
        'issuerKeyHash' => ['type' => ASN1::TYPE_OCTET_STRING],
        'serialNumber' => Maps\CertificateSerialNumber::MAP,
    ]];

    public const REQUEST = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'reqCert' => self::CERT_ID,
        'singleRequestExtensions' => Maps\Extensions::MAP + ['constant' => 0, 'explicit' => true, 'optional' => true],
    ]];

    public const TBS_REQUEST = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'version' => ['type' => ASN1::TYPE_INTEGER, 'constant' => 0, 'explicit' => true, 'optional' => true, 'mapping' => ['v1'], 'default' => 'v1'],
        'requestorName' => Maps\GeneralName::MAP + ['constant' => 1, 'explicit' => true, 'optional' => true],
        'requestList' => ['type' => ASN1::TYPE_SEQUENCE, 'min' => 1, 'max' => -1, 'children' => self::REQUEST],
        'requestExtensions' => Maps\Extensions::MAP + ['constant' => 2, 'explicit' => true, 'optional' => true],
    ]];

    public const OCSP_REQUEST = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'tbsRequest' => self::TBS_REQUEST,
        'optionalSignature' => ['type' => ASN1::TYPE_ANY, 'constant' => 0, 'explicit' => true, 'optional' => true],
    ]];

    public const OCSP_RESPONSE = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'responseStatus' => ['type' => ASN1::TYPE_ENUMERATED, 'mapping' => [0 => 'successful', 1 => 'malformedRequest', 2 => 'internalError', 3 => 'tryLater', 5 => 'sigRequired', 6 => 'unauthorized']],
        'responseBytes' => ['type' => ASN1::TYPE_SEQUENCE, 'constant' => 0, 'explicit' => true, 'optional' => true, 'children' => [
            'responseType' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
            'response' => ['type' => ASN1::TYPE_OCTET_STRING],
        ]],
    ]];

    public const RESPONDER_ID = ['type' => ASN1::TYPE_CHOICE, 'children' => [
        'byName' => Maps\Name::MAP + ['constant' => 1, 'explicit' => true],
        'byKey' => ['type' => ASN1::TYPE_OCTET_STRING, 'constant' => 2, 'explicit' => true],
    ]];

    public const REVOKED_INFO = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'revocationTime' => ['type' => ASN1::TYPE_GENERALIZED_TIME],
        'revocationReason' => Maps\CRLReason::MAP + ['constant' => 0, 'explicit' => true, 'optional' => true],
    ]];

    public const CERT_STATUS = ['type' => ASN1::TYPE_CHOICE, 'children' => [
        'good' => ['type' => ASN1::TYPE_NULL, 'constant' => 0, 'implicit' => true],
        'revoked' => self::REVOKED_INFO + ['constant' => 1, 'implicit' => true],
        'unknown' => ['type' => ASN1::TYPE_NULL, 'constant' => 2, 'implicit' => true],
    ]];

    public const SINGLE_RESPONSE = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'certID' => self::CERT_ID,
        'certStatus' => self::CERT_STATUS,
        'thisUpdate' => ['type' => ASN1::TYPE_GENERALIZED_TIME],
        'nextUpdate' => ['type' => ASN1::TYPE_GENERALIZED_TIME, 'constant' => 0, 'explicit' => true, 'optional' => true],
        'singleExtensions' => Maps\Extensions::MAP + ['constant' => 1, 'explicit' => true, 'optional' => true],
    ]];

    public const RESPONSE_DATA = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'version' => ['type' => ASN1::TYPE_INTEGER, 'constant' => 0, 'explicit' => true, 'optional' => true, 'mapping' => ['v1'], 'default' => 'v1'],
        'responderID' => self::RESPONDER_ID,
        'producedAt' => ['type' => ASN1::TYPE_GENERALIZED_TIME],
        'responses' => ['type' => ASN1::TYPE_SEQUENCE, 'min' => 0, 'max' => -1, 'children' => self::SINGLE_RESPONSE],
        'responseExtensions' => Maps\Extensions::MAP + ['constant' => 1, 'explicit' => true, 'optional' => true],
    ]];

    public const BASIC_OCSP_RESPONSE = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'tbsResponseData' => self::RESPONSE_DATA,
        'signatureAlgorithm' => Maps\AlgorithmIdentifier::MAP,
        'signature' => ['type' => ASN1::TYPE_BIT_STRING],
        'certs' => ['type' => ASN1::TYPE_SEQUENCE, 'constant' => 0, 'explicit' => true, 'optional' => true, 'min' => 0, 'max' => -1, 'children' => ['type' => ASN1::TYPE_ANY]],
    ]];

    private function __construct() {}
}
