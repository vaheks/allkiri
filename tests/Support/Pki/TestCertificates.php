<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Pki;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\KeyPair;
use Allkiri\Crypto\Phpseclib;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\RSA;
use phpseclib3\File\X509;

/**
 * Certificates issued on the spot, by the committed test CA or by a CA issued
 * in the test, for subjects, extensions and algorithms the committed fixtures
 * do not have.
 *
 * The fixtures under tests/fixtures/pki are not regenerated for this, because
 * generate.sh replaces the CA and the RSA signer certificate is registered with
 * SK's demo service.
 */
final class TestCertificates
{
    /** The responder the committed signer and card certificates name. */
    public const OCSP_URL = 'http://ocsp.allkiri.test/';

    private function __construct() {}

    /**
     * A certificate for a key: the key of an existing test key pair, or one
     * made in the test.
     *
     * Basic constraints, a digitalSignature key usage and the test responder's
     * address are added unless $extensions says otherwise; a null value leaves
     * that extension out.
     *
     * @param array<string, string>                  $subject    phpseclib DN property names, such as `id-at-serialNumber`, to values
     * @param array<string, array{mixed, bool}|null> $extensions phpseclib extension names to their value and criticality
     * @param TestIssuer|null                        $issuer     the committed test CA when null
     */
    public static function issue(
        KeyPair|TestKey $key,
        array $subject,
        array $extensions = [],
        ?TestIssuer $issuer = null,
        TestCertificateSignature $signature = TestCertificateSignature::Sha256,
    ): KeyPair {
        $issuer ??= TestIssuer::ca();
        $signer = new X509();
        if ($signer->loadX509($issuer->certificate->pem()) === false) {
            throw new \LogicException('The issuer certificate did not load');
        }
        $signer->setPrivateKey(self::signingKey($issuer->key, $signature));

        $holder = new X509();
        $holder->setPublicKey($key instanceof KeyPair ? $key->certificate->publicKey() : $key->publicKey());
        foreach ($subject as $property => $value) {
            if ($holder->setDNProp($property, $value) === false) {
                throw new \LogicException(\sprintf('phpseclib does not know the subject attribute "%s"', $property));
            }
        }

        $x509 = new X509();
        $x509->setStartDate('2020-01-01 00:00:00 UTC');
        $x509->setEndDate('2050-01-01 00:00:00 UTC');
        $x509->setSerialNumber(bin2hex(random_bytes(8)), 16);
        $unsigned = $x509->sign($signer, $holder);
        if (!\is_array($unsigned) || $x509->loadX509($unsigned) === false) {
            throw new \LogicException('The certificate could not be issued');
        }

        $extensions += [
            'id-ce-basicConstraints' => [['cA' => false], true],
            'id-ce-keyUsage' => [['digitalSignature'], true],
            'id-pe-authorityInfoAccess' => [[['accessMethod' => 'id-ad-ocsp', 'accessLocation' => ['uniformResourceIdentifier' => self::OCSP_URL]]], false],
        ];
        foreach ($extensions as $name => $extension) {
            if ($extension === null) {
                continue;
            }
            [$value, $critical] = $extension;
            if ($x509->setExtension($name, $value, $critical) === false) {
                throw new \LogicException(\sprintf('phpseclib refused the extension "%s"', $name));
            }
        }

        $signed = $x509->sign($signer, $x509);
        $pem = \is_array($signed) ? $x509->saveX509($signed) : false;
        if (!\is_string($pem)) {
            throw new \LogicException('The certificate could not be signed');
        }

        return new KeyPair($key->privateKey, Certificate::fromPem($pem), [$issuer->certificate]);
    }

    private static function signingKey(TestKey $key, TestCertificateSignature $signature): PrivateKey
    {
        $raw = $key->raw;
        if ($raw instanceof RSA\PrivateKey) {
            // phpseclib signs with RSASSA-PSS unless told otherwise.
            return Phpseclib::rsaPrivate(Phpseclib::rsaPrivate($raw->withPadding(RSA::SIGNATURE_PKCS1))->withHash($signature->hashName()));
        }

        return Phpseclib::ecPrivate($raw->withHash($signature->hashName()));
    }
}
