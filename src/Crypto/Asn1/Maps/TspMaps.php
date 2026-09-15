<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Asn1\Maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;

/**
 * RFC 3161 Time-Stamp Protocol structures.
 *
 * @internal
 */
final class TspMaps
{
    public const MESSAGE_IMPRINT = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'hashAlgorithm' => Maps\AlgorithmIdentifier::MAP,
        'hashedMessage' => ['type' => ASN1::TYPE_OCTET_STRING],
    ]];

    public const TIME_STAMP_REQ = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'version' => ['type' => ASN1::TYPE_INTEGER],
        'messageImprint' => self::MESSAGE_IMPRINT,
        'reqPolicy' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER, 'optional' => true],
        'nonce' => ['type' => ASN1::TYPE_INTEGER, 'optional' => true],
        'certReq' => ['type' => ASN1::TYPE_BOOLEAN, 'optional' => true, 'default' => false],
        'extensions' => Maps\Extensions::MAP + ['constant' => 0, 'implicit' => true, 'optional' => true],
    ]];

    public const PKI_STATUS_INFO = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'status' => ['type' => ASN1::TYPE_INTEGER],
        'statusString' => ['type' => ASN1::TYPE_SEQUENCE, 'optional' => true, 'min' => 0, 'max' => -1, 'children' => ['type' => ASN1::TYPE_UTF8_STRING]],
        'failInfo' => ['type' => ASN1::TYPE_BIT_STRING, 'optional' => true],
    ]];

    public const TIME_STAMP_RESP = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'status' => self::PKI_STATUS_INFO,
        'timeStampToken' => CmsMaps::CONTENT_INFO + ['optional' => true],
    ]];

    public const ACCURACY = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'seconds' => ['type' => ASN1::TYPE_INTEGER, 'optional' => true],
        'millis' => ['type' => ASN1::TYPE_INTEGER, 'constant' => 0, 'implicit' => true, 'optional' => true],
        'micros' => ['type' => ASN1::TYPE_INTEGER, 'constant' => 1, 'implicit' => true, 'optional' => true],
    ]];

    public const TST_INFO = ['type' => ASN1::TYPE_SEQUENCE, 'children' => [
        'version' => ['type' => ASN1::TYPE_INTEGER],
        'policy' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
        'messageImprint' => self::MESSAGE_IMPRINT,
        'serialNumber' => ['type' => ASN1::TYPE_INTEGER],
        'genTime' => ['type' => ASN1::TYPE_GENERALIZED_TIME],
        'accuracy' => self::ACCURACY + ['optional' => true],
        'ordering' => ['type' => ASN1::TYPE_BOOLEAN, 'optional' => true, 'default' => false],
        'nonce' => ['type' => ASN1::TYPE_INTEGER, 'optional' => true],
        'tsa' => Maps\GeneralName::MAP + ['constant' => 0, 'explicit' => true, 'optional' => true],
        'extensions' => Maps\Extensions::MAP + ['constant' => 1, 'implicit' => true, 'optional' => true],
    ]];

    private function __construct() {}
}
