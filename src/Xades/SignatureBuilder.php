<?php

declare(strict_types=1);

namespace Allkiri\Xades;

use Allkiri\Container\DataFile;
use Allkiri\Container\SignatureFile;
use Allkiri\Crypto\Asn1\Asn1;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Xml\Dsig\CanonicalizationException;
use Allkiri\Xml\Dsig\Canonicalizer;
use Allkiri\Xml\Dsig\DsigNs;
use Psr\Clock\ClockInterface;

/**
 * Builds the XAdES-BES skeleton of a signature: everything that is signed,
 * plus the empty SignatureValue the signer will fill in.
 *
 * The element order and naming follow what digidoc4j produces, because that
 * is what DigiDoc4 and SiVa are known to accept.
 */
final class SignatureBuilder
{
    public function __construct(
        private readonly ClockInterface $clock,
        private readonly Canonicalizer $canonicalizer = new Canonicalizer(),
    ) {}

    /**
     * @param list<DataFile> $dataFiles
     */
    public function build(array $dataFiles, Certificate $signer, SignatureAlgorithm $algorithm, SignatureProfile $profile = new SignatureProfile()): BuiltSignature
    {
        if ($dataFiles === []) {
            throw new InvalidArgumentException('A signature must cover at least one data file');
        }
        if (!Canonicalizer::supports($profile->canonicalizationMethod)) {
            throw new CanonicalizationException(\sprintf('Cannot sign with canonicalization method "%s"', $profile->canonicalizationMethod));
        }

        // digidoc4j names signatures "id-<32 hex>"; derive it from what is being
        // signed so that signing the same files with the same key twice gives
        // the same document.
        $seed = $signer->der() . implode('', array_map(static fn(DataFile $f): string => $f->name . $f->digest(), $dataFiles));
        $id = $profile->signatureId ?? 'id-' . substr(hash('sha256', $seed), 0, 32);

        $document = new \DOMDocument('1.0', 'UTF-8');
        $document->preserveWhiteSpace = true;
        $document->formatOutput = false;

        $root = $document->createElementNS(SignatureFile::NS_ASIC, 'asic:XAdESSignatures');
        $document->appendChild($root);
        $signature = $document->createElementNS(DsigNs::DS, 'ds:Signature');
        $signature->setAttribute('Id', $id);
        $root->appendChild($signature);

        $signedInfo = $this->signedInfo($document, $signature, $dataFiles, $algorithm, $profile, $id);

        $signatureValue = $document->createElementNS(DsigNs::DS, 'ds:SignatureValue');
        $signatureValue->setAttribute('Id', 'value-' . $id);
        $signature->appendChild($signatureValue);

        $keyInfo = $document->createElementNS(DsigNs::DS, 'ds:KeyInfo');
        $x509Data = $document->createElementNS(DsigNs::DS, 'ds:X509Data');
        $x509Data->appendChild($document->createElementNS(DsigNs::DS, 'ds:X509Certificate', $signer->base64()));
        $keyInfo->appendChild($x509Data);
        $signature->appendChild($keyInfo);

        $signedProperties = $this->qualifyingProperties($document, $signature, $dataFiles, $signer, $profile, $id);

        // The SignedProperties digest can only be computed once the element exists.
        $reference = $this->signedPropertiesReference($signedInfo);
        $canonical = $this->canonicalizer->canonicalize($signedProperties, $profile->canonicalizationMethod);
        $this->setDigestValue($reference, $profile->digestAlgorithm->digest($canonical));

        $signedInfoCanonical = $this->canonicalizer->canonicalize($signedInfo, $profile->canonicalizationMethod);

        return new BuiltSignature(SignatureDocument::wrap($document), $id, $signedInfoCanonical, $algorithm->hash());
    }

    /**
     * @param list<DataFile> $dataFiles
     */
    private function signedInfo(\DOMDocument $document, \DOMElement $signature, array $dataFiles, SignatureAlgorithm $algorithm, SignatureProfile $profile, string $id): \DOMElement
    {
        $signedInfo = $document->createElementNS(DsigNs::DS, 'ds:SignedInfo');
        $signature->appendChild($signedInfo);

        $c14n = $document->createElementNS(DsigNs::DS, 'ds:CanonicalizationMethod');
        $c14n->setAttribute('Algorithm', $profile->canonicalizationMethod);
        $signedInfo->appendChild($c14n);

        $method = $document->createElementNS(DsigNs::DS, 'ds:SignatureMethod');
        $method->setAttribute('Algorithm', $algorithm->xmlUri());
        $signedInfo->appendChild($method);

        foreach ($dataFiles as $index => $file) {
            $reference = $document->createElementNS(DsigNs::DS, 'ds:Reference');
            $reference->setAttribute('Id', self::referenceId($id, $index));
            $reference->setAttribute('URI', self::encodeUri($file->name));
            $this->appendDigest($document, $reference, $profile, $file->digest($profile->digestAlgorithm));
            $signedInfo->appendChild($reference);
        }

        $reference = $document->createElementNS(DsigNs::DS, 'ds:Reference');
        $reference->setAttribute('Type', Ns::TYPE_SIGNED_PROPERTIES);
        $reference->setAttribute('URI', '#xades-' . $id);
        $transforms = $document->createElementNS(DsigNs::DS, 'ds:Transforms');
        $transform = $document->createElementNS(DsigNs::DS, 'ds:Transform');
        $transform->setAttribute('Algorithm', $profile->canonicalizationMethod);
        $transforms->appendChild($transform);
        $reference->appendChild($transforms);
        $this->appendDigest($document, $reference, $profile, '');
        $signedInfo->appendChild($reference);

        return $signedInfo;
    }

    /**
     * @param list<DataFile> $dataFiles
     */
    private function qualifyingProperties(\DOMDocument $document, \DOMElement $signature, array $dataFiles, Certificate $signer, SignatureProfile $profile, string $id): \DOMElement
    {
        $object = $document->createElementNS(DsigNs::DS, 'ds:Object');
        $signature->appendChild($object);
        $qualifying = $document->createElementNS(Ns::XADES, 'xades:QualifyingProperties');
        $qualifying->setAttribute('Target', '#' . $id);
        $object->appendChild($qualifying);

        $signedProperties = $document->createElementNS(Ns::XADES, 'xades:SignedProperties');
        $signedProperties->setAttribute('Id', 'xades-' . $id);
        $qualifying->appendChild($signedProperties);

        $signatureProperties = $document->createElementNS(Ns::XADES, 'xades:SignedSignatureProperties');
        $signedProperties->appendChild($signatureProperties);
        $signatureProperties->appendChild($document->createElementNS(Ns::XADES, 'xades:SigningTime', $this->clock->now()->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z')));
        $signatureProperties->appendChild($this->signingCertificate($document, $signer, $profile));
        if ($profile->hasProductionPlace()) {
            $signatureProperties->appendChild($this->productionPlace($document, $profile));
        }
        if ($profile->claimedRoles !== []) {
            $signatureProperties->appendChild($this->signerRole($document, $profile));
        }

        $dataObjectProperties = $document->createElementNS(Ns::XADES, 'xades:SignedDataObjectProperties');
        $signedProperties->appendChild($dataObjectProperties);
        foreach ($dataFiles as $index => $file) {
            $format = $document->createElementNS(Ns::XADES, 'xades:DataObjectFormat');
            $format->setAttribute('ObjectReference', '#' . self::referenceId($id, $index));
            $format->appendChild($document->createElementNS(Ns::XADES, 'xades:MimeType', $file->mimeType));
            $dataObjectProperties->appendChild($format);
        }

        return $signedProperties;
    }

    private function signingCertificate(\DOMDocument $document, Certificate $signer, SignatureProfile $profile): \DOMElement
    {
        $v2 = $profile->useSigningCertificateV2;
        $element = $document->createElementNS(Ns::XADES, $v2 ? 'xades:SigningCertificateV2' : 'xades:SigningCertificate');
        $cert = $document->createElementNS(Ns::XADES, 'xades:Cert');
        $element->appendChild($cert);

        $digest = $document->createElementNS(Ns::XADES, 'xades:CertDigest');
        $method = $document->createElementNS(DsigNs::DS, 'ds:DigestMethod');
        $method->setAttribute('Algorithm', $profile->digestAlgorithm->xmlUri());
        $digest->appendChild($method);
        $digest->appendChild($document->createElementNS(DsigNs::DS, 'ds:DigestValue', base64_encode($signer->fingerprint($profile->digestAlgorithm))));
        $cert->appendChild($digest);

        if ($v2) {
            // IssuerSerialV2 is base64 of an RFC 5035 IssuerSerial:
            //   SEQUENCE { GeneralNames { [4] EXPLICIT Name }, INTEGER serial }
            // built from the issuer's exact DER name so the bytes match the
            // certificate rather than a re-encoding of it.
            $issuerSerial = Asn1::sequence([
                Asn1::sequence([Asn1::explicit(4, $signer->issuerNameDer())]),
                Asn1::integer($signer->serialNumber()),
            ]);
            $cert->appendChild($document->createElementNS(Ns::XADES, 'xades:IssuerSerialV2', base64_encode($issuerSerial)));
        } else {
            $issuerSerial = $document->createElementNS(Ns::XADES, 'xades:IssuerSerial');
            $issuerSerial->appendChild($document->createElementNS(DsigNs::DS, 'ds:X509IssuerName', $signer->issuerDn()));
            $issuerSerial->appendChild($document->createElementNS(DsigNs::DS, 'ds:X509SerialNumber', $signer->serialNumber()));
            $cert->appendChild($issuerSerial);
        }

        return $element;
    }

    private function productionPlace(\DOMDocument $document, SignatureProfile $profile): \DOMElement
    {
        $place = $document->createElementNS(Ns::XADES, 'xades:SignatureProductionPlaceV2');
        foreach ([
            'xades:City' => $profile->city,
            'xades:StateOrProvince' => $profile->stateOrProvince,
            'xades:PostalCode' => $profile->postalCode,
            'xades:CountryName' => $profile->country,
        ] as $name => $value) {
            if ($value !== null) {
                $place->appendChild($document->createElementNS(Ns::XADES, $name, $value));
            }
        }

        return $place;
    }

    private function signerRole(\DOMDocument $document, SignatureProfile $profile): \DOMElement
    {
        $role = $document->createElementNS(Ns::XADES, 'xades:SignerRoleV2');
        $claimed = $document->createElementNS(Ns::XADES, 'xades:ClaimedRoles');
        foreach ($profile->claimedRoles as $text) {
            $claimed->appendChild($document->createElementNS(Ns::XADES, 'xades:ClaimedRole', $text));
        }
        $role->appendChild($claimed);

        return $role;
    }

    private function appendDigest(\DOMDocument $document, \DOMElement $reference, SignatureProfile $profile, string $digest): void
    {
        $method = $document->createElementNS(DsigNs::DS, 'ds:DigestMethod');
        $method->setAttribute('Algorithm', $profile->digestAlgorithm->xmlUri());
        $reference->appendChild($method);
        $reference->appendChild($document->createElementNS(DsigNs::DS, 'ds:DigestValue', $digest === '' ? '' : base64_encode($digest)));
    }

    private function signedPropertiesReference(\DOMElement $signedInfo): \DOMElement
    {
        foreach ($signedInfo->getElementsByTagNameNS(DsigNs::DS, 'Reference') as $reference) {
            if ($reference->getAttribute('Type') === Ns::TYPE_SIGNED_PROPERTIES) {
                return $reference;
            }
        }

        throw new SignatureStructureException('The SignedProperties reference disappeared while building');
    }

    private function setDigestValue(\DOMElement $reference, string $digest): void
    {
        foreach ($reference->getElementsByTagNameNS(DsigNs::DS, 'DigestValue') as $value) {
            $value->textContent = base64_encode($digest);

            return;
        }

        throw new SignatureStructureException('A reference has no DigestValue');
    }

    private static function referenceId(string $signatureId, int $index): string
    {
        return \sprintf('r-%s-%d', $signatureId, $index + 1);
    }

    /**
     * Percent-encode a file name for a reference URI, keeping the path separators.
     */
    private static function encodeUri(string $name): string
    {
        return implode('/', array_map(static fn(string $segment): string => rawurlencode($segment), explode('/', $name)));
    }
}
