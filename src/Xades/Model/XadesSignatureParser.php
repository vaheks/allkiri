<?php

declare(strict_types=1);

namespace Allkiri\Xades\Model;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\CertificateException;
use Allkiri\Xades\Ns;
use Allkiri\Xml\Xml;

/**
 * Builds the {@see XadesSignature} read model from a ds:Signature element.
 *
 * Tolerant by design: anything missing or malformed becomes a null, an empty
 * list or a warning, so the validator can report rather than crash.
 */
final class XadesSignatureParser
{
    public function parse(\DOMElement $signature): XadesSignature
    {
        $xpath = Xml::xpath($signature, Ns::PREFIXES);
        $warnings = [];

        $signedInfo = Xml::element($xpath, 'ds:SignedInfo', $signature);
        $references = [];
        if ($signedInfo === null) {
            $warnings[] = 'ds:SignedInfo missing';
        } else {
            foreach (Xml::elements($xpath, 'ds:Reference', $signedInfo) as $reference) {
                $references[] = [
                    'id' => $reference->getAttribute('Id'),
                    'uri' => $reference->getAttribute('URI'),
                    'type' => $reference->getAttribute('Type'),
                    'digestMethod' => Xml::attribute($xpath, 'ds:DigestMethod/@Algorithm', $reference),
                    'digestValue' => Xml::base64($xpath, 'ds:DigestValue', $reference) ?? '',
                    'transforms' => Xml::attributes($xpath, 'ds:Transforms/ds:Transform/@Algorithm', $reference),
                ];
            }
        }

        $keyInfoCertificates = $this->certificates($xpath, 'ds:KeyInfo/ds:X509Data/ds:X509Certificate', $signature, $warnings, 'ds:KeyInfo');

        $ownSignedProperties = Xml::element($xpath, 'ds:Object/xades:QualifyingProperties/xades:SignedProperties', $signature);
        $unboundReference = self::unboundSignedPropertiesReference($signature, $references, $ownSignedProperties);
        $signedProperties = $unboundReference === null ? $ownSignedProperties : null;
        $signingTime = null;
        $signingCertificateIsV2 = false;
        $signingCertificateReferences = [];
        $dataObjectFormats = [];
        $hasPolicy = false;
        $claimedRoles = [];
        $productionPlace = null;
        if ($signedProperties === null) {
            $warnings[] = $unboundReference === null
                ? 'xades:SignedProperties missing'
                : \sprintf('The signed properties reference "%s" does not resolve to this signature\'s own xades:SignedProperties, so they are not read', $unboundReference);
        } else {
            $time = Xml::text($xpath, 'xades:SignedSignatureProperties/xades:SigningTime', $signedProperties);
            if ($time !== null) {
                try {
                    $signingTime = (new \DateTimeImmutable(trim($time)))->setTimezone(new \DateTimeZone('UTC'));
                } catch (\Exception) {
                    $warnings[] = \sprintf('Unparseable SigningTime "%s"', trim($time));
                }
            }

            $v2 = Xml::elements($xpath, 'xades:SignedSignatureProperties/xades:SigningCertificateV2/xades:Cert', $signedProperties);
            $signingCertificateIsV2 = $v2 !== [];
            $certs = $signingCertificateIsV2 ? $v2 : Xml::elements($xpath, 'xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert', $signedProperties);
            foreach ($certs as $cert) {
                $signingCertificateReferences[] = [
                    'digestMethod' => Xml::attribute($xpath, 'xades:CertDigest/ds:DigestMethod/@Algorithm', $cert),
                    'digest' => Xml::base64($xpath, 'xades:CertDigest/ds:DigestValue', $cert) ?? '',
                    'issuerSerialV2' => Xml::base64($xpath, 'xades:IssuerSerialV2', $cert),
                    'issuerName' => Xml::text($xpath, 'xades:IssuerSerial/ds:X509IssuerName', $cert),
                    'serialNumber' => Xml::text($xpath, 'xades:IssuerSerial/ds:X509SerialNumber', $cert),
                ];
            }

            $hasPolicy = Xml::element($xpath, 'xades:SignedSignatureProperties/xades:SignaturePolicyIdentifier', $signedProperties) !== null;

            foreach (Xml::elements($xpath, 'xades:SignedDataObjectProperties/xades:DataObjectFormat', $signedProperties) as $format) {
                $dataObjectFormats[] = [
                    'objectReference' => $format->getAttribute('ObjectReference'),
                    'mimeType' => trim(Xml::text($xpath, 'xades:MimeType', $format) ?? ''),
                ];
            }

            // SignerRole in XAdES 1.3.2, SignerRoleV2 in EN 319 132-1.
            foreach (Xml::elements($xpath, 'xades:SignedSignatureProperties/*[local-name()="SignerRole" or local-name()="SignerRoleV2"]/xades:ClaimedRoles/xades:ClaimedRole', $signedProperties) as $role) {
                $claimedRoles[] = trim($role->textContent);
            }
            $place = Xml::element($xpath, 'xades:SignedSignatureProperties/*[local-name()="SignatureProductionPlace" or local-name()="SignatureProductionPlaceV2"]', $signedProperties);
            if ($place !== null) {
                $parts = [];
                foreach (Xml::elements($xpath, '*', $place) as $child) {
                    if (trim($child->textContent) !== '') {
                        $parts[] = trim($child->textContent);
                    }
                }
                $productionPlace = $parts === [] ? null : implode(', ', $parts);
            }
        }

        $unsigned = Xml::element($xpath, 'ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties', $signature);
        $signatureTimestamps = [];
        $certificateValues = [];
        $ocspValues = [];
        $crlValueCount = 0;
        $archiveTimestampCount = 0;
        if ($unsigned !== null) {
            foreach (Xml::elements($xpath, 'xades:SignatureTimeStamp', $unsigned) as $timestamp) {
                $token = Xml::base64($xpath, 'xades:EncapsulatedTimeStamp', $timestamp);
                if ($token === null) {
                    $warnings[] = 'xades:SignatureTimeStamp without a token';
                    continue;
                }
                $signatureTimestamps[] = [
                    'id' => $timestamp->getAttribute('Id'),
                    'canonicalizationMethod' => Xml::attribute($xpath, 'ds:CanonicalizationMethod/@Algorithm', $timestamp),
                    'token' => $token,
                ];
            }
            $certificateValues = $this->certificates($xpath, 'xades:CertificateValues/xades:EncapsulatedX509Certificate', $unsigned, $warnings, 'xades:CertificateValues');
            foreach (Xml::elements($xpath, 'xades:RevocationValues/xades:OCSPValues/xades:EncapsulatedOCSPValue', $unsigned) as $ocsp) {
                $der = Xml::decodeBase64($ocsp->textContent);
                if ($der === null) {
                    $warnings[] = 'xades:EncapsulatedOCSPValue is not base64';
                    continue;
                }
                $ocspValues[] = $der;
            }
            $crlValueCount = \count(Xml::elements($xpath, 'xades:RevocationValues/xades:CRLValues/xades:EncapsulatedCRLValue', $unsigned));
            $archiveTimestampCount = \count(Xml::elements($xpath, 'xadesv141:ArchiveTimeStamp', $unsigned));
        }

        return new XadesSignature(
            $signature,
            $signature->getAttribute('Id'),
            $signedInfo === null ? '' : Xml::attribute($xpath, 'ds:SignatureMethod/@Algorithm', $signedInfo),
            $signedInfo === null ? '' : Xml::attribute($xpath, 'ds:CanonicalizationMethod/@Algorithm', $signedInfo),
            $references,
            Xml::base64($xpath, 'ds:SignatureValue', $signature),
            $keyInfoCertificates,
            $signingTime,
            $signingCertificateIsV2,
            $signingCertificateReferences,
            $dataObjectFormats,
            $hasPolicy,
            $signatureTimestamps,
            $certificateValues,
            $ocspValues,
            $crlValueCount,
            $archiveTimestampCount,
            $claimedRoles,
            $productionPlace,
            $warnings,
            $unboundReference,
        );
    }

    /**
     * The URI of the signed-properties reference when it resolves to anything
     * other than this signature's own SignedProperties. Null when it resolves
     * there, or when there is no such reference, which the policy judges.
     *
     * The verifier digests whatever the reference resolves to. Reading the
     * properties by position instead would let an untouched copy placed
     * elsewhere be digested while altered properties inside the signature are
     * reported, and the signature would still verify. So the two have to be
     * the same element before anything is read from them.
     *
     * @param list<array{id: string, uri: string, type: string, digestMethod: string, digestValue: string, transforms: list<string>}> $references
     */
    private static function unboundSignedPropertiesReference(\DOMElement $signature, array $references, ?\DOMElement $own): ?string
    {
        foreach ($references as $reference) {
            if (!\in_array($reference['type'], [Ns::TYPE_SIGNED_PROPERTIES, Ns::TYPE_SIGNED_PROPERTIES_V111], true)) {
                continue;
            }
            $document = $signature->ownerDocument;
            $referenced = $document !== null && str_starts_with($reference['uri'], '#')
                ? Xml::elementById($document, substr($reference['uri'], 1))
                : null;

            return $own !== null && $referenced !== null && $referenced->isSameNode($own) ? null : $reference['uri'];
        }

        return null;
    }

    /**
     * @param list<string> $warnings
     *
     * @return list<Certificate>
     */
    private function certificates(\DOMXPath $xpath, string $query, \DOMNode $context, array &$warnings, string $where): array
    {
        $certificates = [];
        foreach (Xml::elements($xpath, $query, $context) as $node) {
            try {
                $certificates[] = Certificate::fromBase64($node->textContent);
            } catch (CertificateException $e) {
                $warnings[] = \sprintf('%s contains an unparseable certificate: %s', $where, $e->getMessage());
            }
        }

        return $certificates;
    }
}
