<?php

declare(strict_types=1);

namespace Allkiri\Crypto;

use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use phpseclib3\File\ASN1;
use phpseclib3\File\X509;

/**
 * An X.509 certificate that never forgets its original DER.
 *
 * phpseclib rewrites parts of a certificate while parsing it (the public key
 * becomes PEM), so every byte-exact need (signature verification, OCSP
 * CertID hashes, XAdES IssuerSerial, embedding) is served from raw slices of
 * the DER this object was created from.
 */
final class Certificate
{
    private const DN_PROPS = [
        'CN' => ['id-at-commonName'],
        'SN' => ['id-at-surname'],
        'GN' => ['id-at-givenName'],
        'serialNumber' => ['id-at-serialNumber'],
        'C' => ['id-at-countryName'],
        'O' => ['id-at-organizationName'],
        'OU' => ['id-at-organizationalUnitName'],
        'organizationIdentifier' => ['id-at-organizationIdentifier', '2.5.4.97'],
    ];

    private const EKU_OIDS = [
        'id-kp-serverAuth' => '1.3.6.1.5.5.7.3.1',
        'id-kp-clientAuth' => '1.3.6.1.5.5.7.3.2',
        'id-kp-codeSigning' => '1.3.6.1.5.5.7.3.3',
        'id-kp-emailProtection' => '1.3.6.1.5.5.7.3.4',
        'id-kp-timeStamping' => '1.3.6.1.5.5.7.3.8',
        'id-kp-OCSPSigning' => '1.3.6.1.5.5.7.3.9',
    ];

    public const OID_OCSP_NOCHECK = '1.3.6.1.5.5.7.48.1.5';

    private ?PublicKey $publicKey = null;

    /** @var array<string, mixed>|null */
    private ?array $root = null;

    /**
     * @param array<string, mixed> $parsed
     */
    private function __construct(
        private readonly string $der,
        private readonly X509 $x509,
        private readonly array $parsed,
    ) {}

    public static function fromDer(string $der): self
    {
        $x509 = new X509();
        $parsed = $x509->loadX509($der, X509::FORMAT_DER);
        if (!\is_array($parsed) || !isset($parsed['tbsCertificate'])) {
            throw new CertificateException('Not a DER-encoded X.509 certificate');
        }
        /** @var array<string, mixed> $parsed */

        return new self($der, $x509, $parsed);
    }

    public static function fromPem(string $pem): self
    {
        if (preg_match('/-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s', $pem, $match) !== 1) {
            throw new CertificateException('No PEM certificate block found');
        }

        return self::fromBase64($match[1]);
    }

    public static function fromBase64(string $base64): self
    {
        $der = base64_decode((string) preg_replace('/\s+/', '', $base64), true);
        if ($der === false || $der === '') {
            throw new CertificateException('Certificate is not valid base64');
        }

        return self::fromDer($der);
    }

    public function der(): string
    {
        return $this->der;
    }

    public function base64(): string
    {
        return base64_encode($this->der);
    }

    public function pem(): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split($this->base64(), 64, "\n") . "-----END CERTIFICATE-----\n";
    }

    // --- identity -----------------------------------------------------------

    public function subjectDn(): string
    {
        $dn = $this->x509->getSubjectDN(X509::DN_STRING);

        return \is_string($dn) ? $dn : '';
    }

    public function issuerDn(): string
    {
        $dn = $this->x509->getIssuerDN(X509::DN_STRING);

        return \is_string($dn) ? $dn : '';
    }

    /**
     * A subject attribute by short name: CN, SN, GN, serialNumber, C, O, OU, organizationIdentifier.
     */
    public function subjectAttribute(string $name): ?string
    {
        foreach (self::DN_PROPS[$name] ?? [$name] as $prop) {
            $values = $this->x509->getSubjectDNProp($prop);
            if (\is_array($values) && $values !== []) {
                return self::scalarValue($values[0]);
            }
        }

        return null;
    }

    public function commonName(): ?string
    {
        return $this->subjectAttribute('CN');
    }

    /**
     * Decimal serial number.
     */
    public function serialNumber(): string
    {
        $tbs = $this->tbs();
        $serial = $tbs['serialNumber'] ?? null;
        if (!$serial instanceof \phpseclib3\Math\BigInteger) {
            throw new CertificateException('Certificate has no serial number');
        }

        return $serial->toString();
    }

    public function notBefore(): \DateTimeImmutable
    {
        return $this->validityTime('notBefore');
    }

    public function notAfter(): \DateTimeImmutable
    {
        return $this->validityTime('notAfter');
    }

    public function isValidAt(\DateTimeInterface $time): bool
    {
        $ts = $time->getTimestamp();

        return $ts >= $this->notBefore()->getTimestamp() && $ts <= $this->notAfter()->getTimestamp();
    }

    // --- key ----------------------------------------------------------------

    public function publicKey(): PublicKey
    {
        if ($this->publicKey === null) {
            $key = $this->x509->getPublicKey();
            if (!$key instanceof PublicKey) {
                throw new CertificateException('Certificate public key could not be loaded');
            }
            $this->publicKey = $key;
        }

        return $this->publicKey;
    }

    public function keyType(): KeyType
    {
        return KeyType::of($this->publicKey());
    }

    /**
     * Key size in bits: modulus size for RSA, curve size for EC.
     */
    public function keyBits(): int
    {
        $key = $this->publicKey();
        if (!$key instanceof RSA\PublicKey && !$key instanceof EC\PublicKey) {
            throw new UnsupportedAlgorithmException(\sprintf('Unsupported public key type %s', $key::class));
        }

        return Phpseclib::int($key->getLength());
    }

    /**
     * Named curve of an EC key ("secp256r1"); null for RSA keys and for keys
     * with explicit (unnamed) curve parameters.
     */
    public function curveName(): ?string
    {
        $key = $this->publicKey();
        if (!$key instanceof EC\PublicKey) {
            return null;
        }
        $curve = $key->getCurve();

        return \is_string($curve) ? $curve : null;
    }

    /**
     * The subjectPublicKey BIT STRING content without the unused-bits octet,
     * as hashed into an OCSP CertID issuerKeyHash.
     */
    public function subjectPublicKeyBytes(): string
    {
        $bits = self::children($this->tbsField(5))[1]['content'] ?? null;
        if (!\is_string($bits) || $bits === '') {
            throw new CertificateException('Malformed subjectPublicKeyInfo');
        }

        return substr($bits, 1);
    }

    /**
     * DER of the whole SubjectPublicKeyInfo, whose SHA-256 is the TLS public-key pin.
     */
    public function subjectPublicKeyInfoDer(): string
    {
        return $this->slice($this->tbsField(5));
    }

    // --- raw DER slices ------------------------------------------------------

    public function tbsCertificateDer(): string
    {
        return $this->slice(self::children($this->root())[0]);
    }

    public function issuerNameDer(): string
    {
        return $this->slice($this->tbsField(2));
    }

    public function subjectNameDer(): string
    {
        return $this->slice($this->tbsField(4));
    }

    public function signatureAlgorithmOid(): string
    {
        $oid = self::children(self::children($this->root())[1])[0]['content'] ?? null;
        if (!\is_string($oid)) {
            throw new CertificateException('Malformed signature algorithm');
        }

        return $oid;
    }

    /**
     * The signature BIT STRING content without the unused-bits octet.
     */
    public function signatureValue(): string
    {
        $bits = self::children($this->root())[2]['content'] ?? null;
        if (!\is_string($bits) || $bits === '') {
            throw new CertificateException('Malformed certificate signature');
        }

        return substr($bits, 1);
    }

    // --- extensions ---------------------------------------------------------

    public function subjectKeyIdentifier(): ?string
    {
        $value = $this->x509->getExtension('id-ce-subjectKeyIdentifier');

        return \is_string($value) && $value !== '' ? $value : null;
    }

    public function authorityKeyIdentifier(): ?string
    {
        $value = $this->x509->getExtension('id-ce-authorityKeyIdentifier');
        if (!\is_array($value)) {
            return null;
        }
        $id = $value['keyIdentifier'] ?? null;

        return \is_string($id) && $id !== '' ? $id : null;
    }

    public function isCa(): bool
    {
        $value = $this->x509->getExtension('id-ce-basicConstraints');

        return \is_array($value) && ($value['cA'] ?? false) === true;
    }

    /**
     * @return list<string> key usage names as in RFC 5280 ("digitalSignature", "nonRepudiation", "keyCertSign", ...)
     */
    public function keyUsage(): array
    {
        $value = $this->x509->getExtension('id-ce-keyUsage');

        return \is_array($value) ? array_values(array_filter($value, is_string(...))) : [];
    }

    /**
     * @return list<string> extended key usage OIDs in dotted form
     */
    public function extendedKeyUsage(): array
    {
        $value = $this->x509->getExtension('id-ce-extKeyUsage');
        if (!\is_array($value)) {
            return [];
        }
        $oids = [];
        foreach ($value as $item) {
            if (\is_string($item)) {
                $oids[] = self::EKU_OIDS[$item] ?? $item;
            }
        }

        return $oids;
    }

    /**
     * @param string $usage a dotted OID or one of the id-kp-* names
     */
    public function hasExtendedKeyUsage(string $usage): bool
    {
        return \in_array(self::EKU_OIDS[$usage] ?? $usage, $this->extendedKeyUsage(), true);
    }

    /**
     * @param string $extension dotted OID or phpseclib name
     */
    public function hasExtension(string $extension): bool
    {
        $ids = $this->x509->getExtensions();
        if (!\is_array($ids)) {
            return false;
        }
        foreach ($ids as $id) {
            if ($id === $extension || (\is_string($id) && ASN1::getOID($id) === $extension)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<string> OCSP responder URLs from the Authority Information Access extension
     */
    public function ocspUrls(): array
    {
        return $this->accessLocations(['id-ad-ocsp', 'id-pkix-ocsp', '1.3.6.1.5.5.7.48.1']);
    }

    /**
     * @return list<string> CA issuer certificate URLs from the Authority Information Access extension
     */
    public function caIssuersUrls(): array
    {
        return $this->accessLocations(['id-ad-caIssuers', '1.3.6.1.5.5.7.48.2']);
    }

    // --- relations ----------------------------------------------------------

    /**
     * Cryptographic check only: the issuer's public key verifies this
     * certificate's signature. Validity dates and trust are the caller's job.
     *
     * @throws UnsupportedAlgorithmException when the certificate's own signature algorithm is not implemented
     */
    public function isSignedBy(Certificate $issuer): bool
    {
        return (new PublicKeyVerifier())->verifyWithOid(
            $issuer->publicKey(),
            $this->signatureAlgorithmOid(),
            $this->tbsCertificateDer(),
            $this->signatureValue(),
        );
    }

    public function isSelfSigned(): bool
    {
        if ($this->subjectNameDer() !== $this->issuerNameDer()) {
            return false;
        }

        try {
            return $this->isSignedBy($this);
        } catch (UnsupportedAlgorithmException) {
            return false;
        }
    }

    public function fingerprint(HashAlgorithm $algorithm = HashAlgorithm::SHA256): string
    {
        return $algorithm->digest($this->der);
    }

    public function equals(Certificate $other): bool
    {
        return $this->der === $other->der;
    }

    // --- internals ----------------------------------------------------------

    /**
     * @return array<string, mixed>
     */
    private function tbs(): array
    {
        $tbs = $this->parsed['tbsCertificate'] ?? null;
        if (!\is_array($tbs)) {
            throw new CertificateException('Malformed certificate');
        }
        /** @var array<string, mixed> $tbs */

        return $tbs;
    }

    private function validityTime(string $field): \DateTimeImmutable
    {
        $validity = $this->tbs()['validity'] ?? null;
        $time = \is_array($validity) ? ($validity[$field] ?? null) : null;
        $text = \is_array($time) ? ($time['utcTime'] ?? $time['generalTime'] ?? null) : null;
        if (!\is_string($text)) {
            throw new CertificateException(\sprintf('Certificate has no %s', $field));
        }

        try {
            return (new \DateTimeImmutable($text))->setTimezone(new \DateTimeZone('UTC'));
        } catch (\Exception $e) {
            throw new CertificateException(\sprintf('Unparseable %s "%s"', $field, $text), 0, $e);
        }
    }

    /**
     * @param list<string> $methods accepted accessMethod spellings
     *
     * @return list<string>
     */
    private function accessLocations(array $methods): array
    {
        $aia = $this->x509->getExtension('id-pe-authorityInfoAccess');
        if (!\is_array($aia)) {
            return [];
        }
        $urls = [];
        foreach ($aia as $entry) {
            if (!\is_array($entry) || !\in_array($entry['accessMethod'] ?? null, $methods, true)) {
                continue;
            }
            $location = $entry['accessLocation'] ?? null;
            $url = \is_array($location) ? ($location['uniformResourceIdentifier'] ?? null) : null;
            if (\is_string($url) && $url !== '') {
                $urls[] = $url;
            }
        }

        return $urls;
    }

    /**
     * The root decodeBER node of the certificate SEQUENCE.
     *
     * @return array<string, mixed>
     */
    private function root(): array
    {
        if ($this->root === null) {
            $decoded = ASN1::decodeBER($this->der);
            $root = \is_array($decoded) ? ($decoded[0] ?? null) : null;
            if (!\is_array($root)) {
                throw new CertificateException('Malformed certificate DER');
            }
            /** @var array<string, mixed> $root */
            $this->root = $root;
        }

        return $this->root;
    }

    /**
     * tbsCertificate field by position after the optional version:
     * 0 serialNumber, 1 signature, 2 issuer, 3 validity, 4 subject, 5 subjectPublicKeyInfo.
     *
     * @return array<string, mixed>
     */
    private function tbsField(int $index): array
    {
        $fields = self::children(self::children($this->root())[0]);
        $offset = \array_key_exists('constant', $fields[0]) ? 1 : 0;

        return $fields[$index + $offset] ?? throw new CertificateException('Malformed tbsCertificate');
    }

    /**
     * @param array<string, mixed> $node
     *
     * @return list<array<string, mixed>>
     */
    private static function children(array $node): array
    {
        $content = $node['content'] ?? null;
        if (!\is_array($content)) {
            throw new CertificateException('Malformed certificate structure');
        }
        $children = [];
        foreach ($content as $child) {
            if (!\is_array($child)) {
                throw new CertificateException('Malformed certificate structure');
            }
            /** @var array<string, mixed> $child */
            $children[] = $child;
        }

        return $children;
    }

    /**
     * @param array<string, mixed> $node
     */
    private function slice(array $node): string
    {
        $start = $node['start'] ?? null;
        $length = $node['length'] ?? null;
        if (!\is_int($start) || !\is_int($length)) {
            throw new CertificateException('Malformed certificate structure');
        }

        return substr($this->der, $start, $length);
    }

    private static function scalarValue(mixed $value): ?string
    {
        if (\is_string($value)) {
            return $value;
        }
        if (\is_array($value)) {
            foreach ($value as $inner) {
                if (\is_string($inner)) {
                    return $inner;
                }
            }
        }

        return null;
    }
}
