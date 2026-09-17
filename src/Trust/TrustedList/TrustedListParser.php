<?php

declare(strict_types=1);

namespace Allkiri\Trust\TrustedList;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\CertificateException;
use Allkiri\Trust\ServiceStatus;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustAnchor;
use Allkiri\Xml\InvalidXmlException;
use Allkiri\Xml\Xml;

/**
 * Reads an ETSI TS 119 612 trusted list into trust anchors.
 *
 * Only the service types allkiri can use become anchors (CA, OCSP and TSA);
 * each one carries the status history from the list, so a signature made
 * while a service was granted stays valid after the status changes.
 *
 * @internal
 */
final class TrustedListParser
{
    public const NS_TSL = 'http://uri.etsi.org/02231/v2#';
    public const NS_ADDITIONAL = 'http://uri.etsi.org/02231/v2/additionaltypes#';

    /**
     * @throws TrustedListException
     */
    public function parse(string $xml, string $source = 'trusted-list'): TrustedList
    {
        try {
            $document = Xml::load($xml);
        } catch (InvalidXmlException $e) {
            throw new TrustedListException(TrustedListException::REASON_MALFORMED, 'Trusted list is not well-formed XML: ' . $e->getMessage(), $e);
        }
        $xpath = Xml::xpath($document, ['tsl' => self::NS_TSL]);
        $root = $document->documentElement;
        if ($root === null || $root->localName !== 'TrustServiceStatusList') {
            throw new TrustedListException(TrustedListException::REASON_MALFORMED, 'Document is not a TrustServiceStatusList');
        }

        $info = Xml::element($xpath, 'tsl:SchemeInformation', $root)
            ?? throw new TrustedListException(TrustedListException::REASON_MALFORMED, 'Trusted list has no SchemeInformation');

        $territory = trim(Xml::text($xpath, 'tsl:SchemeTerritory', $info) ?? '');
        $operator = trim(Xml::text($xpath, 'tsl:SchemeOperatorName/tsl:Name', $info) ?? '');
        $sequence = (int) trim(Xml::text($xpath, 'tsl:TSLSequenceNumber', $info) ?? '0');
        $issueDate = self::time(Xml::text($xpath, 'tsl:ListIssueDateTime', $info));
        $nextUpdate = self::time(Xml::text($xpath, 'tsl:NextUpdate/tsl:dateTime', $info));
        // Every anchor remembers its list, so validation can tell when a signature rests on one that is overdue.
        $listStatus = new TrustedListStatus($source, $nextUpdate);

        $anchors = [];
        foreach (Xml::elements($xpath, 'tsl:TrustServiceProviderList/tsl:TrustServiceProvider', $root) as $provider) {
            $providerName = trim(Xml::text($xpath, 'tsl:TSPInformation/tsl:TSPName/tsl:Name', $provider) ?? '');
            foreach (Xml::elements($xpath, 'tsl:TSPServices/tsl:TSPService', $provider) as $service) {
                foreach ($this->anchorsOfService($xpath, $service, $providerName, $source, $listStatus) as $anchor) {
                    $anchors[] = $anchor;
                }
            }
        }

        $pointers = [];
        foreach (Xml::elements($xpath, 'tsl:SchemeInformation/tsl:PointersToOtherTSL/tsl:OtherTSLPointer', $root) as $pointer) {
            $parsed = $this->pointer($xpath, $pointer);
            if ($parsed !== null) {
                $pointers[] = $parsed;
            }
        }

        $schemeInformationUris = [];
        foreach (Xml::elements($xpath, 'tsl:SchemeInformationURI/tsl:URI', $info) as $uri) {
            $value = trim($uri->textContent);
            if ($value !== '') {
                $schemeInformationUris[] = $value;
            }
        }

        return new TrustedList($territory, $operator, $sequence, $issueDate, $nextUpdate, $anchors, $pointers, $schemeInformationUris);
    }

    /**
     * @return list<TrustAnchor>
     */
    private function anchorsOfService(\DOMXPath $xpath, \DOMElement $service, string $providerName, string $source, TrustedListStatus $listStatus): array
    {
        $info = Xml::element($xpath, 'tsl:ServiceInformation', $service);
        if ($info === null) {
            return [];
        }
        $type = ServiceType::tryFrom(trim(Xml::text($xpath, 'tsl:ServiceTypeIdentifier', $info) ?? ''));
        if ($type === null) {
            return []; // a service type allkiri has no use for
        }
        $name = trim(Xml::text($xpath, 'tsl:ServiceName/tsl:Name', $info) ?? '');
        if ($name === '') {
            $name = $providerName;
        }

        $history = [];
        $currentStatus = ServiceStatus::tryFrom(trim(Xml::text($xpath, 'tsl:ServiceStatus', $info) ?? ''));
        $currentSince = self::time(Xml::text($xpath, 'tsl:StatusStartingTime', $info));
        if ($currentStatus !== null) {
            $history[] = ['status' => $currentStatus, 'since' => $currentSince ?? new \DateTimeImmutable('@0')];
        }
        foreach (Xml::elements($xpath, 'tsl:ServiceHistory/tsl:ServiceHistoryInstance', $service) as $instance) {
            $status = ServiceStatus::tryFrom(trim(Xml::text($xpath, 'tsl:ServiceStatus', $instance) ?? ''));
            $since = self::time(Xml::text($xpath, 'tsl:StatusStartingTime', $instance));
            if ($status !== null) {
                $history[] = ['status' => $status, 'since' => $since ?? new \DateTimeImmutable('@0')];
            }
        }
        if ($history === []) {
            return [];
        }

        $anchors = [];
        foreach (Xml::elements($xpath, 'tsl:ServiceDigitalIdentity/tsl:DigitalId/tsl:X509Certificate', $info) as $node) {
            try {
                $certificate = Certificate::fromBase64($node->textContent);
            } catch (CertificateException) {
                continue; // a digital identity we cannot read is simply not an anchor
            }
            $anchors[] = new TrustAnchor($certificate, $type, $name, $history, $source, $listStatus);
        }

        return $anchors;
    }

    private function pointer(\DOMXPath $xpath, \DOMElement $pointer): ?TrustedListPointer
    {
        $location = trim(Xml::text($xpath, 'tsl:TSLLocation', $pointer) ?? '');
        if ($location === '') {
            return null;
        }
        $territory = '';
        $mimeType = null;
        foreach (Xml::elements($xpath, 'tsl:AdditionalInformation/tsl:OtherInformation/*', $pointer) as $other) {
            if ($other->localName === 'SchemeTerritory') {
                $territory = trim($other->textContent);
            }
            if ($other->localName === 'MimeType') {
                $mimeType = trim($other->textContent);
            }
        }
        $certificates = [];
        foreach (Xml::elements($xpath, 'tsl:ServiceDigitalIdentities/tsl:ServiceDigitalIdentity/tsl:DigitalId/tsl:X509Certificate', $pointer) as $node) {
            try {
                $certificates[] = Certificate::fromBase64($node->textContent);
            } catch (CertificateException) {
                continue;
            }
        }

        return new TrustedListPointer($territory, $location, $certificates, $mimeType);
    }

    private static function time(?string $text): ?\DateTimeImmutable
    {
        if ($text === null || trim($text) === '') {
            return null;
        }

        try {
            return (new \DateTimeImmutable(trim($text)))->setTimezone(new \DateTimeZone('UTC'));
        } catch (\Exception) {
            return null;
        }
    }
}
