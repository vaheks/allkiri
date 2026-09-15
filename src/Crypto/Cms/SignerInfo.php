<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Cms;

use Allkiri\Crypto\Asn1\Asn1Exception;
use Allkiri\Crypto\Asn1\Maps\CmsMaps;
use Allkiri\Crypto\Asn1\Node;
use Allkiri\Crypto\Asn1\Oids;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\SignatureAlgorithmIdentifier;
use Allkiri\Crypto\UnsupportedAlgorithmException;
use phpseclib3\File\ASN1 as PhpseclibAsn1;
use phpseclib3\Math\BigInteger;

/**
 * A CMS SignerInfo with the signed attributes kept as exact bytes.
 */
final class SignerInfo
{
    private readonly string $digestAlgorithmOid;

    private readonly string $signatureAlgorithmOid;

    private readonly string $signatureAlgorithmDer;

    private readonly string $signature;

    private readonly ?string $signedAttrsDer;

    /** @var array<string, list<Node>> attribute OID => value nodes */
    private readonly array $signedAttributes;

    private readonly ?string $sidIssuerNameDer;

    private readonly ?string $sidSerialNumber;

    private readonly ?string $sidSubjectKeyIdentifier;

    /**
     * @param array<mixed> $mapped
     *
     * @internal
     */
    public function __construct(array $mapped, Node $node)
    {
        $digest = $mapped['digestAlgorithm'] ?? null;
        $signatureAlgorithm = $mapped['signatureAlgorithm'] ?? null;
        $signature = $mapped['signature'] ?? null;
        if (!\is_array($digest) || !\is_string($digest['algorithm'] ?? null) || !\is_array($signatureAlgorithm) || !\is_string($signatureAlgorithm['algorithm'] ?? null) || !\is_string($signature)) {
            throw new Asn1Exception('Malformed SignerInfo');
        }
        $this->digestAlgorithmOid = Oids::dotted($digest['algorithm']);
        $this->signatureAlgorithmOid = Oids::dotted($signatureAlgorithm['algorithm']);
        $this->signature = $signature;

        $sid = $mapped['sid'] ?? null;
        $issuerAndSerial = \is_array($sid) ? ($sid['issuerAndSerialNumber'] ?? null) : null;
        if (\is_array($issuerAndSerial)) {
            $sidNode = $node->child(1);
            $this->sidIssuerNameDer = $sidNode->child(0)->der();
            $serial = $issuerAndSerial['serialNumber'] ?? null;
            $this->sidSerialNumber = $serial instanceof BigInteger ? $serial->toString() : null;
            $this->sidSubjectKeyIdentifier = null;
        } else {
            $ski = \is_array($sid) ? ($sid['subjectKeyIdentifier'] ?? null) : null;
            $this->sidIssuerNameDer = null;
            $this->sidSerialNumber = null;
            $this->sidSubjectKeyIdentifier = \is_string($ski) ? $ski : null;
        }

        // signedAttrs is the [0]-tagged element right after digestAlgorithm; a
        // subjectKeyIdentifier sid is [0]-tagged too, so do not search by tag alone.
        $children = $node->children();
        $attrsNode = isset($children[3]) && $children[3]->isTagged() && $children[3]->tag() === 0 ? $children[3] : null;
        $attributes = [];
        if ($attrsNode !== null) {
            $der = $attrsNode->der();
            // RFC 5652 §5.4: the signature covers the attributes with a SET OF tag, not the [0] IMPLICIT one.
            $der[0] = "\x31";
            $this->signedAttrsDer = $der;
            foreach ($attrsNode->children() as $attribute) {
                $attributes[$attribute->child(0)->oid()] = $attribute->child(1)->children();
            }
        } else {
            $this->signedAttrsDer = null;
        }
        $this->signedAttributes = $attributes;
        // signatureAlgorithm comes right after signedAttrs, or after digestAlgorithm when there are none.
        $this->signatureAlgorithmDer = $node->child($attrsNode !== null ? 4 : 3)->der();
    }

    public function digestAlgorithmOid(): string
    {
        return $this->digestAlgorithmOid;
    }

    public function signatureAlgorithmOid(): string
    {
        return $this->signatureAlgorithmOid;
    }

    /**
     * The signature algorithm with its parameters.
     *
     * @throws UnsupportedAlgorithmException when it is not one allkiri verifies
     */
    public function signatureAlgorithm(): SignatureAlgorithmIdentifier
    {
        return SignatureAlgorithmIdentifier::fromDer($this->signatureAlgorithmDer);
    }

    public function signature(): string
    {
        return $this->signature;
    }

    /**
     * The bytes the signature was computed over (SET OF Attribute DER), or null when unsigned attributes are absent.
     */
    public function signedAttrsDer(): ?string
    {
        return $this->signedAttrsDer;
    }

    public function hasSignedAttribute(string $oid): bool
    {
        return isset($this->signedAttributes[$oid]);
    }

    /**
     * The first value of a signed attribute as a raw DER node.
     *
     * @internal
     */
    public function signedAttribute(string $oid): ?Node
    {
        return $this->signedAttributes[$oid][0] ?? null;
    }

    public function contentTypeAttribute(): ?string
    {
        return $this->signedAttribute(Oids::ID_CONTENT_TYPE)?->oid();
    }

    public function messageDigestAttribute(): ?string
    {
        $node = $this->signedAttribute(Oids::ID_MESSAGE_DIGEST);
        if ($node === null || $node->isTagged() || $node->type() !== PhpseclibAsn1::TYPE_OCTET_STRING) {
            return null;
        }

        return $node->string();
    }

    public function signingTimeAttribute(): ?\DateTimeImmutable
    {
        return $this->signedAttribute(Oids::ID_SIGNING_TIME)?->time();
    }

    /**
     * The ESS signing-certificate references (v2 preferred, v1 accepted).
     *
     * @return list<EssCertId>
     */
    public function signingCertificateReferences(): array
    {
        $v2 = $this->signedAttribute(Oids::ID_AA_SIGNING_CERTIFICATE_V2);
        if ($v2 !== null) {
            return self::essIds($v2->map(CmsMaps::SIGNING_CERTIFICATE_V2)->array('certs'), true);
        }
        $v1 = $this->signedAttribute(Oids::ID_AA_SIGNING_CERTIFICATE);
        if ($v1 !== null) {
            return self::essIds($v1->map(CmsMaps::SIGNING_CERTIFICATE)->array('certs'), false);
        }

        return [];
    }

    /**
     * The certificate this SignerInfo identifies, among the candidates.
     *
     * @param list<Certificate> $candidates
     */
    public function findSigner(array $candidates): ?Certificate
    {
        foreach ($candidates as $candidate) {
            if ($this->sidIssuerNameDer !== null) {
                if ($candidate->issuerNameDer() === $this->sidIssuerNameDer && $candidate->serialNumber() === $this->sidSerialNumber) {
                    return $candidate;
                }
            } elseif ($this->sidSubjectKeyIdentifier !== null && $candidate->subjectKeyIdentifier() === $this->sidSubjectKeyIdentifier) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * @param array<mixed> $certs
     *
     * @return list<EssCertId>
     */
    private static function essIds(array $certs, bool $v2): array
    {
        $ids = [];
        foreach ($certs as $cert) {
            if (\is_array($cert)) {
                $ids[] = EssCertId::fromMapped($cert, $v2);
            }
        }

        return $ids;
    }
}
