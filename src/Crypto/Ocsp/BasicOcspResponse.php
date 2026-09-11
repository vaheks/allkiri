<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Ocsp;

use Allkiri\Crypto\Asn1\Asn1;
use Allkiri\Crypto\Asn1\Asn1Exception;
use Allkiri\Crypto\Asn1\Maps\OcspMaps;
use Allkiri\Crypto\Asn1\Oids;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\HashAlgorithm;

/**
 * A parsed BasicOCSPResponse that keeps the exact bytes the responder signed.
 */
final class BasicOcspResponse
{
    /** @var list<SingleResponse> */
    private readonly array $responses;

    /** @var list<Certificate> */
    private readonly array $certificates;

    private readonly string $tbsResponseDataDer;

    private readonly string $signatureAlgorithmOid;

    private readonly string $signature;

    private readonly ?string $responderName;

    private readonly ?string $responderKeyHash;

    private readonly \DateTimeImmutable $producedAt;

    private readonly ?string $nonce;

    private function __construct(private readonly string $der)
    {
        $decoded = Asn1::decode($der, OcspMaps::BASIC_OCSP_RESPONSE);
        $root = $decoded->node();
        $tbsNode = $root->child(0);
        $this->tbsResponseDataDer = $tbsNode->der();
        $this->signatureAlgorithmOid = Oids::dotted($decoded->string('signatureAlgorithm', 'algorithm'));
        $this->signature = $root->child(2)->bitStringBytes();

        $responderId = $decoded->array('tbsResponseData', 'responderID');
        $tbsChildren = $tbsNode->children();
        // responderID is the first child after the optional [0] version.
        $responderNode = $tbsChildren[0]->isTagged() && $tbsChildren[0]->tag() === 0 ? $tbsChildren[1] : $tbsChildren[0];
        $offset = $responderNode === $tbsChildren[0] ? 0 : 1;
        $this->responderName = isset($responderId['byName']) ? $responderNode->child(0)->der() : null;
        $this->responderKeyHash = isset($responderId['byKey']) ? $responderNode->child(0)->string() : null;
        $this->producedAt = $tbsChildren[$offset + 1]->time();

        $responses = [];
        $responsesNode = $tbsChildren[$offset + 2];
        foreach ($decoded->array('tbsResponseData', 'responses') as $index => $mapped) {
            if (!\is_array($mapped) || !\is_int($index)) {
                throw new Asn1Exception('Malformed responses');
            }
            $responses[] = SingleResponse::fromMapped($mapped, $responsesNode->child($index));
        }
        $this->responses = $responses;

        $extensions = $decoded->get('tbsResponseData', 'responseExtensions');
        $this->nonce = \is_array($extensions) ? OcspRequest::nonceFromExtensions($extensions) : null;

        $certificates = [];
        $certsNode = $root->tagged(0);
        if ($certsNode !== null) {
            foreach ($certsNode->child(0)->children() as $certNode) {
                $certificates[] = Certificate::fromDer($certNode->der());
            }
        }
        $this->certificates = $certificates;
    }

    public static function fromDer(string $der): self
    {
        return new self($der);
    }

    public function der(): string
    {
        return $this->der;
    }

    /**
     * Exactly the bytes the responder signed.
     */
    public function tbsResponseDataDer(): string
    {
        return $this->tbsResponseDataDer;
    }

    public function signatureAlgorithmOid(): string
    {
        return $this->signatureAlgorithmOid;
    }

    public function signature(): string
    {
        return $this->signature;
    }

    /**
     * DER Name of the responder when identified byName.
     */
    public function responderName(): ?string
    {
        return $this->responderName;
    }

    /**
     * SHA-1 of the responder's public key when identified byKey.
     */
    public function responderKeyHash(): ?string
    {
        return $this->responderKeyHash;
    }

    public function producedAt(): \DateTimeImmutable
    {
        return $this->producedAt;
    }

    /**
     * @return list<SingleResponse>
     */
    public function responses(): array
    {
        return $this->responses;
    }

    public function nonce(): ?string
    {
        return $this->nonce;
    }

    /**
     * @return list<Certificate> certificates shipped in the response, responder first by convention
     */
    public function certificates(): array
    {
        return $this->certificates;
    }

    /**
     * The certificate the responderID points at, among the given candidates.
     *
     * @param list<Certificate> $candidates
     */
    public function findResponder(array $candidates): ?Certificate
    {
        foreach ($candidates as $candidate) {
            if ($this->responderName !== null && $candidate->subjectNameDer() === $this->responderName) {
                return $candidate;
            }
            if ($this->responderKeyHash !== null && hash_equals(sha1($candidate->subjectPublicKeyBytes(), true), $this->responderKeyHash)) {
                return $candidate;
            }
        }

        return null;
    }

    public function fingerprint(): string
    {
        return HashAlgorithm::SHA256->digest($this->der);
    }
}
