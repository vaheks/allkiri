<?php

declare(strict_types=1);

namespace Allkiri\Xades;

use Allkiri\Xades\Dsig\Xml;

/**
 * Puts the signature value into a built signature.
 */
final class SignatureCompleter
{
    public function setSignatureValue(SignatureDocument $document, string $signatureId, string $signatureValue): void
    {
        $signature = $document->signature($signatureId) ?? throw new SignatureStructureException(\sprintf('No signature "%s" in the document', $signatureId));
        $element = Xml::element($document->xpath(), 'ds:SignatureValue', $signature)
            ?? throw new SignatureStructureException('The signature has no ds:SignatureValue element');
        // Single-line base64: line breaks would survive canonicalisation and
        // some validators are stricter about them than the specification is.
        $element->textContent = base64_encode($signatureValue);
    }
}
