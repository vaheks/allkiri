<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Xades;

use Allkiri\Xades\Ns;
use Allkiri\Xades\SignatureDocument;
use Allkiri\Xml\Xml;

/**
 * XML signature wrapping, built from a genuine signature file.
 *
 * An untouched copy of the signed properties goes where the reference will
 * find it, so the digest still matches and the signature still verifies. The
 * properties inside the signature are then altered to claim another signing
 * time. A validator that reports anything it did not digest reports the
 * forgery.
 */
final class SignatureWrapping
{
    public const FORGED_SIGNING_TIME = '2099-01-01T00:00:00Z';

    private function __construct() {}

    /**
     * The copy keeps the Id, so two elements carry it.
     */
    public static function duplicateId(string $signatureXml): string
    {
        return self::forge($signatureXml, false);
    }

    /**
     * The original is renamed, so every Id is unique and only the element the
     * reference actually resolves to tells the copy from the original.
     */
    public static function renamedOriginal(string $signatureXml): string
    {
        return self::forge($signatureXml, true);
    }

    private static function forge(string $signatureXml, bool $renameOriginal): string
    {
        $document = SignatureDocument::parse($signatureXml);
        $signature = $document->signatures()[0] ?? throw new \LogicException('No ds:Signature to wrap');
        $root = $document->document()->documentElement ?? throw new \LogicException('No document element');
        $xpath = Xml::xpath($signature, Ns::PREFIXES);
        $signedProperties = Xml::element($xpath, 'ds:Object/xades:QualifyingProperties/xades:SignedProperties', $signature)
            ?? throw new \LogicException('No xades:SignedProperties to copy');
        $signingTime = Xml::element($xpath, 'xades:SignedSignatureProperties/xades:SigningTime', $signedProperties)
            ?? throw new \LogicException('No xades:SigningTime to alter');

        $copy = $signedProperties->cloneNode(true);
        if (!$copy instanceof \DOMNode) {
            throw new \LogicException('The signed properties could not be copied');
        }
        $root->insertBefore($copy, $root->firstChild);
        if ($renameOriginal) {
            $signedProperties->setAttribute('Id', 'renamed-' . $signedProperties->getAttribute('Id'));
        }
        $signingTime->textContent = self::FORGED_SIGNING_TIME;

        return $document->toXml();
    }
}
