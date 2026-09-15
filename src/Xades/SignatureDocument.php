<?php

declare(strict_types=1);

namespace Allkiri\Xades;

use Allkiri\Xml\Dsig\DsigNs;
use Allkiri\Xml\InvalidXmlException;
use Allkiri\Xml\Xml;

/**
 * A signatures*.xml document (or any XML carrying ds:Signature elements),
 * loaded by the hardened loader and searched with the XAdES prefixes.
 */
final class SignatureDocument
{
    private function __construct(private readonly \DOMDocument $document) {}

    /**
     * @throws InvalidXmlException when the bytes are empty, not well-formed, or carry a DOCTYPE
     */
    public static function parse(string $xml): self
    {
        return new self(Xml::load($xml));
    }

    public static function wrap(\DOMDocument $document): self
    {
        return new self($document);
    }

    public function document(): \DOMDocument
    {
        return $this->document;
    }

    public function xpath(): \DOMXPath
    {
        return Xml::xpath($this->document, Ns::PREFIXES);
    }

    /**
     * @return list<\DOMElement> every ds:Signature in document order
     */
    public function signatures(): array
    {
        $signatures = [];
        foreach ($this->document->getElementsByTagNameNS(DsigNs::DS, 'Signature') as $element) {
            $signatures[] = $element;
        }

        return $signatures;
    }

    public function signature(string $id): ?\DOMElement
    {
        foreach ($this->signatures() as $signature) {
            if ($signature->getAttribute('Id') === $id) {
                return $signature;
            }
        }

        return null;
    }

    /**
     * Serialised without any reformatting.
     */
    public function toXml(): string
    {
        $xml = $this->document->saveXML();
        if (!\is_string($xml)) {
            throw new SignatureStructureException('Document could not be serialised');
        }

        return $xml;
    }
}
