<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Trust;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\KeyPair;
use Allkiri\Trust\ServiceStatus;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustedList\TrustedListParser;
use Allkiri\Trust\TrustedList\TrustedListPointer;
use Allkiri\Trust\TrustedList\TrustedListVerifier;
use Allkiri\Xml\Dsig\Canonicalizer;
use Allkiri\Xml\Dsig\DsigNs;

/**
 * Small trusted lists, signed with test keys, in the shape the European ones
 * have: enough of ETSI TS 119 612 for the parser, and an enveloped XML
 * signature the verifier accepts.
 *
 * The real lists are signed by keys nobody here holds, so a list of lists
 * signed by a certificate that only a pivot list introduced can only be made
 * this way.
 */
final class TestTrustedLists
{
    private const TSL = TrustedListParser::NS_TSL;

    private const ADDITIONAL = TrustedListParser::NS_ADDITIONAL;

    /**
     * A list of lists, or a pivot list: the two have the same shape.
     *
     * @param list<Certificate> $selfSigners           what its entry for itself names
     * @param list<string>      $schemeInformationUris newest first, as the Commission lists them
     * @param list<array{territory: string, location: string, signers: list<Certificate>}> $territories
     */
    public static function listOfLists(
        KeyPair $signedBy,
        array $selfSigners,
        array $schemeInformationUris,
        string $location,
        array $territories = [],
        int $sequence = 1,
    ): string {
        [$document, $info] = self::skeleton('EU', 'European Commission', $sequence, $schemeInformationUris);
        $pointers = $info->appendChild($document->createElementNS(self::TSL, 'PointersToOtherTSL'));
        self::pointer($pointers, 'EU', $location, $selfSigners);
        foreach ($territories as $territory) {
            self::pointer($pointers, $territory['territory'], $territory['location'], $territory['signers']);
        }
        self::dates($info);

        return self::sign($document, $signedBy);
    }

    /**
     * A national list naming one certificate authority.
     */
    public static function nationalList(KeyPair $signedBy, string $territory, Certificate $authority): string
    {
        [$document, $info] = self::skeleton($territory, 'Test supervisor', 1, []);
        self::dates($info);

        $root = $document->documentElement;
        \assert($root !== null);
        $providers = $root->appendChild($document->createElementNS(self::TSL, 'TrustServiceProviderList'));
        $provider = $providers->appendChild($document->createElementNS(self::TSL, 'TrustServiceProvider'));
        $tspName = $provider->appendChild($document->createElementNS(self::TSL, 'TSPInformation'))
            ->appendChild($document->createElementNS(self::TSL, 'TSPName'));
        self::name($tspName, 'Test provider');
        $service = $provider->appendChild($document->createElementNS(self::TSL, 'TSPServices'))
            ->appendChild($document->createElementNS(self::TSL, 'TSPService'))
            ->appendChild($document->createElementNS(self::TSL, 'ServiceInformation'));
        $service->appendChild($document->createElementNS(self::TSL, 'ServiceTypeIdentifier', ServiceType::CaQc->value));
        self::name($service->appendChild($document->createElementNS(self::TSL, 'ServiceName')), 'Test CA');
        $service->appendChild($document->createElementNS(self::TSL, 'ServiceDigitalIdentity'))
            ->appendChild($document->createElementNS(self::TSL, 'DigitalId'))
            ->appendChild($document->createElementNS(self::TSL, 'X509Certificate', $authority->base64()));
        $service->appendChild($document->createElementNS(self::TSL, 'ServiceStatus', ServiceStatus::Granted->value));
        $service->appendChild($document->createElementNS(self::TSL, 'StatusStartingTime', '2020-01-01T00:00:00Z'));

        return self::sign($document, $signedBy);
    }

    /**
     * @param list<string> $schemeInformationUris
     *
     * @return array{\DOMDocument, \DOMElement}
     */
    private static function skeleton(string $territory, string $operator, int $sequence, array $schemeInformationUris): array
    {
        $document = new \DOMDocument('1.0', 'UTF-8');
        $root = $document->appendChild($document->createElementNS(self::TSL, 'TrustServiceStatusList'));
        \assert($root instanceof \DOMElement);
        $root->setAttribute('Id', 'tsl');
        $info = $root->appendChild($document->createElementNS(self::TSL, 'SchemeInformation'));
        \assert($info instanceof \DOMElement);
        $info->appendChild($document->createElementNS(self::TSL, 'TSLVersionIdentifier', '6'));
        $info->appendChild($document->createElementNS(self::TSL, 'TSLSequenceNumber', (string) $sequence));
        self::name($info->appendChild($document->createElementNS(self::TSL, 'SchemeOperatorName')), $operator);
        if ($schemeInformationUris !== []) {
            $uris = $info->appendChild($document->createElementNS(self::TSL, 'SchemeInformationURI'));
            foreach ($schemeInformationUris as $uri) {
                $element = $uris->appendChild($document->createElementNS(self::TSL, 'URI', $uri));
                \assert($element instanceof \DOMElement);
                $element->setAttributeNS('http://www.w3.org/XML/1998/namespace', 'xml:lang', 'en');
            }
        }
        $info->appendChild($document->createElementNS(self::TSL, 'SchemeTerritory', $territory));

        return [$document, $info];
    }

    /**
     * @param list<Certificate> $signers
     */
    private static function pointer(\DOMNode $pointers, string $territory, string $location, array $signers): void
    {
        $document = $pointers->ownerDocument;
        \assert($document !== null);
        $pointer = $pointers->appendChild($document->createElementNS(self::TSL, 'OtherTSLPointer'));
        $identities = $pointer->appendChild($document->createElementNS(self::TSL, 'ServiceDigitalIdentities'));
        foreach ($signers as $signer) {
            $identities->appendChild($document->createElementNS(self::TSL, 'ServiceDigitalIdentity'))
                ->appendChild($document->createElementNS(self::TSL, 'DigitalId'))
                ->appendChild($document->createElementNS(self::TSL, 'X509Certificate', $signer->base64()));
        }
        $pointer->appendChild($document->createElementNS(self::TSL, 'TSLLocation', $location));
        $information = $pointer->appendChild($document->createElementNS(self::TSL, 'AdditionalInformation'));
        $information->appendChild($document->createElementNS(self::TSL, 'OtherInformation'))
            ->appendChild($document->createElementNS(self::ADDITIONAL, 'ns3:MimeType', TrustedListPointer::MIME_XML));
        $information->appendChild($document->createElementNS(self::TSL, 'OtherInformation'))
            ->appendChild($document->createElementNS(self::TSL, 'SchemeTerritory', $territory));
    }

    private static function dates(\DOMElement $info): void
    {
        $document = $info->ownerDocument;
        \assert($document !== null);
        $info->appendChild($document->createElementNS(self::TSL, 'ListIssueDateTime', '2026-09-01T00:00:00Z'));
        $info->appendChild($document->createElementNS(self::TSL, 'NextUpdate'))
            ->appendChild($document->createElementNS(self::TSL, 'dateTime', '2027-03-01T00:00:00Z'));
    }

    private static function name(\DOMNode $parent, string $name): void
    {
        $document = $parent->ownerDocument;
        \assert($document !== null);
        $element = $parent->appendChild($document->createElementNS(self::TSL, 'Name', $name));
        \assert($element instanceof \DOMElement);
        $element->setAttributeNS('http://www.w3.org/XML/1998/namespace', 'xml:lang', 'en');
    }

    /**
     * An enveloped signature over the whole list, with exclusive
     * canonicalisation and the signer's certificate, as the Commission signs.
     * The result is checked with the library's own verifier before it is used.
     */
    private static function sign(\DOMDocument $document, KeyPair $signer): string
    {
        $root = $document->documentElement;
        \assert($root !== null);
        $canonicalizer = new Canonicalizer();
        $algorithm = $signer->privateKey->defaultAlgorithm();
        $digest = base64_encode(hash('sha256', $canonicalizer->canonicalize($root, DsigNs::C14N_EXC), true));

        $signature = $root->appendChild($document->createElementNS(DsigNs::DS, 'ds:Signature'));
        \assert($signature instanceof \DOMElement);
        $signature->setAttribute('Id', 'tsl-signature');
        $signedInfo = $signature->appendChild($document->createElementNS(DsigNs::DS, 'ds:SignedInfo'));
        \assert($signedInfo instanceof \DOMElement);
        self::withAlgorithm($signedInfo, 'ds:CanonicalizationMethod', DsigNs::C14N_EXC);
        self::withAlgorithm($signedInfo, 'ds:SignatureMethod', $algorithm->xmlUri());
        $reference = $signedInfo->appendChild($document->createElementNS(DsigNs::DS, 'ds:Reference'));
        \assert($reference instanceof \DOMElement);
        $reference->setAttribute('URI', '');
        $transforms = $reference->appendChild($document->createElementNS(DsigNs::DS, 'ds:Transforms'));
        \assert($transforms instanceof \DOMElement);
        self::withAlgorithm($transforms, 'ds:Transform', DsigNs::TRANSFORM_ENVELOPED);
        self::withAlgorithm($transforms, 'ds:Transform', DsigNs::C14N_EXC);
        self::withAlgorithm($reference, 'ds:DigestMethod', HashAlgorithm::SHA256->xmlUri());
        $reference->appendChild($document->createElementNS(DsigNs::DS, 'ds:DigestValue', $digest));

        $value = $signer->privateKey->sign($algorithm, $canonicalizer->canonicalize($signedInfo, DsigNs::C14N_EXC));
        $signature->appendChild($document->createElementNS(DsigNs::DS, 'ds:SignatureValue', base64_encode($value)));
        $signature->appendChild($document->createElementNS(DsigNs::DS, 'ds:KeyInfo'))
            ->appendChild($document->createElementNS(DsigNs::DS, 'ds:X509Data'))
            ->appendChild($document->createElementNS(DsigNs::DS, 'ds:X509Certificate', $signer->certificate->base64()));

        $xml = $document->saveXML();
        \assert(\is_string($xml));
        (new TrustedListVerifier())->verify($xml, [$signer->certificate]);

        return $xml;
    }

    private static function withAlgorithm(\DOMElement $parent, string $name, string $algorithm): void
    {
        $document = $parent->ownerDocument;
        \assert($document !== null);
        $element = $parent->appendChild($document->createElementNS(DsigNs::DS, $name));
        \assert($element instanceof \DOMElement);
        $element->setAttribute('Algorithm', $algorithm);
    }
}
