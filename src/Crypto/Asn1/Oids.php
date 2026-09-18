<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Asn1;

use phpseclib3\File\ASN1;
use phpseclib3\File\X509;

/**
 * Object identifiers allkiri works with, in dotted form.
 *
 * phpseclib names very few of these (and decodes named ones as names, unnamed
 * ones as dotted strings), so every comparison in allkiri goes through
 * {@see Oids::dotted()} and the constants below.
 *
 * @internal
 */
final class Oids
{
    public const SHA1 = '1.3.14.3.2.26';
    public const SHA256 = '2.16.840.1.101.3.4.2.1';
    public const SHA384 = '2.16.840.1.101.3.4.2.2';
    public const SHA512 = '2.16.840.1.101.3.4.2.3';

    public const RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
    public const RSASSA_PSS = '1.2.840.113549.1.1.10';
    public const MGF1 = '1.2.840.113549.1.1.8';
    public const EC_PUBLIC_KEY = '1.2.840.10045.2.1';

    public const ID_PKIX_OCSP_BASIC = '1.3.6.1.5.5.7.48.1.1';
    public const ID_PKIX_OCSP_NONCE = '1.3.6.1.5.5.7.48.1.2';
    public const ID_PKIX_OCSP_NOCHECK = '1.3.6.1.5.5.7.48.1.5';
    public const ID_AD_OCSP = '1.3.6.1.5.5.7.48.1';
    public const ID_AD_CA_ISSUERS = '1.3.6.1.5.5.7.48.2';

    public const ID_KP_TIMESTAMPING = '1.3.6.1.5.5.7.3.8';
    public const ID_KP_OCSP_SIGNING = '1.3.6.1.5.5.7.3.9';

    public const ID_DATA = '1.2.840.113549.1.7.1';
    public const ID_SIGNED_DATA = '1.2.840.113549.1.7.2';
    public const ID_CT_TST_INFO = '1.2.840.113549.1.9.16.1.4';
    public const ID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
    public const ID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
    public const ID_SIGNING_TIME = '1.2.840.113549.1.9.5';
    public const ID_AA_SIGNING_CERTIFICATE = '1.2.840.113549.1.9.16.2.12';
    public const ID_AA_SIGNING_CERTIFICATE_V2 = '1.2.840.113549.1.9.16.2.47';
    public const ID_AA_CMS_ALGORITHM_PROTECTION = '1.2.840.113549.1.9.52';

    /** SK's Estonian timestamp policy seen in demo tokens; informational only. */
    public const SK_TSA_POLICY_QTST = '0.4.0.2023.1.1';

    private static bool $registered = false;

    private function __construct() {}

    /**
     * Make sure phpseclib's OID table is loaded (it registers on first X509
     * construction) and add the names allkiri relies on, using the same names
     * the web-eid library registers so both agree when loaded together.
     */
    public static function register(): void
    {
        if (self::$registered) {
            return;
        }
        new X509();
        ASN1::loadOIDs([
            'id-pkix-ocsp-basic' => self::ID_PKIX_OCSP_BASIC,
            'id-pkix-ocsp-nonce' => self::ID_PKIX_OCSP_NONCE,
            'id-pkix-ocsp-nocheck' => self::ID_PKIX_OCSP_NOCHECK,
            'id-signedData' => self::ID_SIGNED_DATA,
            'id-data' => self::ID_DATA,
            'id-ct-TSTInfo' => self::ID_CT_TST_INFO,
            'id-contentType' => self::ID_CONTENT_TYPE,
            'id-messageDigest' => self::ID_MESSAGE_DIGEST,
            'id-signingTime' => self::ID_SIGNING_TIME,
            'id-aa-signingCertificate' => self::ID_AA_SIGNING_CERTIFICATE,
            'id-aa-signingCertificateV2' => self::ID_AA_SIGNING_CERTIFICATE_V2,
            'id-aa-CMSAlgorithmProtection' => self::ID_AA_CMS_ALGORITHM_PROTECTION,
        ]);
        self::$registered = true;
    }

    /**
     * Dotted form of an OID that phpseclib may have decoded to a name.
     */
    public static function dotted(string $nameOrOid): string
    {
        if (preg_match('/^\d+(\.\d+)+\z/', $nameOrOid) === 1) {
            return $nameOrOid;
        }
        self::register();
        $oid = ASN1::getOID($nameOrOid);

        return \is_string($oid) ? $oid : $nameOrOid;
    }
}
