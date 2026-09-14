<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Pki;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\KeyPair;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\File\X509;

/**
 * Certificates issued on the spot by the committed test CA, for subjects and
 * extensions the committed fixtures do not have.
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
     * A certificate for the key of an existing test key pair.
     *
     * Basic constraints, a digitalSignature key usage and the test responder's
     * address are added unless $extensions says otherwise.
     *
     * @param array<string, string>             $subject    phpseclib DN property names, such as `id-at-serialNumber`, to values
     * @param array<string, array{mixed, bool}> $extensions phpseclib extension names to their value and criticality
     */
    public static function issue(KeyPair $key, array $subject, array $extensions = []): KeyPair
    {
        $ca = TestPki::ca();
        $caKey = PublicKeyLoader::loadPrivateKey((string) file_get_contents(TestPki::DIR . '/ca.key.pem'));
        // phpseclib signs with RSASSA-PSS unless told otherwise; the committed
        // certificates, and the chain verifier, use PKCS#1 v1.5.
        if ($caKey instanceof RSA\PrivateKey) {
            $padded = $caKey->withPadding(RSA::SIGNATURE_PKCS1);
            if (!$padded instanceof RSA\PrivateKey) {
                throw new \LogicException('The test CA key would not take PKCS#1 v1.5 padding');
            }
            $caKey = $padded->withHash('sha256');
        }
        if (!$caKey instanceof PrivateKey) {
            throw new \LogicException('The test CA key did not load');
        }
        $issuer = new X509();
        if ($issuer->loadX509($ca->certificate->pem()) === false) {
            throw new \LogicException('The test CA certificate did not load');
        }
        $issuer->setPrivateKey($caKey);

        $holder = new X509();
        $holder->setPublicKey($key->certificate->publicKey());
        foreach ($subject as $property => $value) {
            if ($holder->setDNProp($property, $value) === false) {
                throw new \LogicException(\sprintf('phpseclib does not know the subject attribute "%s"', $property));
            }
        }

        $x509 = new X509();
        $x509->setStartDate('2020-01-01 00:00:00 UTC');
        $x509->setEndDate('2050-01-01 00:00:00 UTC');
        $x509->setSerialNumber(bin2hex(random_bytes(8)), 16);
        $unsigned = $x509->sign($issuer, $holder);
        if (!\is_array($unsigned) || $x509->loadX509($unsigned) === false) {
            throw new \LogicException('The certificate could not be issued');
        }

        $extensions += [
            'id-ce-basicConstraints' => [['cA' => false], true],
            'id-ce-keyUsage' => [['digitalSignature'], true],
            'id-pe-authorityInfoAccess' => [[['accessMethod' => 'id-ad-ocsp', 'accessLocation' => ['uniformResourceIdentifier' => self::OCSP_URL]]], false],
        ];
        foreach ($extensions as $name => [$value, $critical]) {
            if ($x509->setExtension($name, $value, $critical) === false) {
                throw new \LogicException(\sprintf('phpseclib refused the extension "%s"', $name));
            }
        }

        $signed = $x509->sign($issuer, $x509);
        $pem = \is_array($signed) ? $x509->saveX509($signed) : false;
        if (!\is_string($pem)) {
            throw new \LogicException('The certificate could not be signed');
        }

        return new KeyPair($key->privateKey, Certificate::fromPem($pem), [$ca->certificate]);
    }
}
