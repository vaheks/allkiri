<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Cms;

use Allkiri\Crypto\Asn1\Asn1;
use Allkiri\Crypto\Asn1\Asn1Exception;
use Allkiri\Crypto\Asn1\Maps\CmsMaps;
use Allkiri\Crypto\Asn1\Oids;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\CertificateException;

/**
 * A CMS ContentInfo wrapping SignedData (RFC 5652), parsed with every
 * signature-relevant part kept as original bytes.
 */
final class SignedData
{
    private readonly string $eContentType;

    private readonly ?string $eContent;

    /** @var list<Certificate> */
    private readonly array $certificates;

    /** @var list<SignerInfo> */
    private readonly array $signerInfos;

    private function __construct(private readonly string $contentInfoDer)
    {
        $contentInfo = Asn1::decode($contentInfoDer, CmsMaps::CONTENT_INFO);
        if (Oids::dotted($contentInfo->string('contentType')) !== Oids::ID_SIGNED_DATA) {
            throw new Asn1Exception('ContentInfo is not SignedData');
        }
        $signedDataNode = $contentInfo->node()->tagged(0)?->child(0) ?? throw new Asn1Exception('ContentInfo has no content');
        $signedData = $signedDataNode->map(CmsMaps::SIGNED_DATA);

        $this->eContentType = Oids::dotted($signedData->string('encapContentInfo', 'eContentType'));
        $eContent = $signedData->get('encapContentInfo', 'eContent');
        $this->eContent = \is_string($eContent) ? $eContent : null;

        $certificates = [];
        $certsNode = $signedDataNode->tagged(0);
        if ($certsNode !== null) {
            foreach ($certsNode->children() as $certNode) {
                if ($certNode->isSequence()) {
                    // Reported like any other malformed part of the structure.
                    try {
                        $certificates[] = Certificate::fromDer($certNode->der());
                    } catch (CertificateException $e) {
                        throw new Asn1Exception('Embedded certificate is malformed: ' . $e->getMessage(), 0, $e);
                    }
                }
            }
        }
        $this->certificates = $certificates;

        $signerInfos = [];
        $signerInfosNode = $signedDataNode->child($signedDataNode->childCount() - 1);
        foreach ($signedData->array('signerInfos') as $index => $mapped) {
            if (!\is_array($mapped) || !\is_int($index)) {
                throw new Asn1Exception('Malformed signerInfos');
            }
            $signerInfos[] = new SignerInfo($mapped, $signerInfosNode->child($index));
        }
        $this->signerInfos = $signerInfos;
    }

    public static function fromDer(string $contentInfoDer): self
    {
        return new self($contentInfoDer);
    }

    public function der(): string
    {
        return $this->contentInfoDer;
    }

    public function eContentType(): string
    {
        return $this->eContentType;
    }

    /**
     * The encapsulated content bytes (a TSTInfo DER for timestamp tokens).
     */
    public function eContent(): ?string
    {
        return $this->eContent;
    }

    /**
     * @return list<Certificate>
     */
    public function certificates(): array
    {
        return $this->certificates;
    }

    /**
     * @return list<SignerInfo>
     */
    public function signerInfos(): array
    {
        return $this->signerInfos;
    }
}
