<?php

declare(strict_types=1);

namespace Allkiri\Signing;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\Ocsp\OcspClient;
use Allkiri\Crypto\Ocsp\OcspException;
use Allkiri\Crypto\Tsp\TimestampException;
use Allkiri\Crypto\Tsp\TspClient;
use Allkiri\Trust\CertificateChain;
use Allkiri\Trust\ChainBuilder;
use Allkiri\Trust\ChainBuildingException;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustedList\TrustedListException;
use Allkiri\Trust\TrustStore;
use Allkiri\Xades\Dsig\Canonicalizer;
use Allkiri\Xades\Dsig\Xml;
use Allkiri\Xades\Ns;
use Allkiri\Xades\SignatureDocument;
use Allkiri\Xades\SignatureStructureException;

/**
 * Raises a completed BES signature to T and then to LT.
 *
 * The order is the Estonian practice and is not negotiable: timestamp first,
 * then OCSP, so the revocation answer provably comes after the moment the
 * signature existed.
 */
final class LtExtender
{
    /** digidoc4j warns beyond this; so do we. */
    public const OCSP_DELAY_WARNING_SECONDS = 900;

    public function __construct(
        private readonly TspClient $tspClient,
        private readonly OcspClient $ocspClient,
        private readonly ChainBuilder $chainBuilder,
        private readonly TrustStore $trustStore,
        private readonly Canonicalizer $canonicalizer = new Canonicalizer(),
    ) {}

    public function extend(SignatureDocument $document, \DOMElement $signature, Certificate $signer, SignatureLevel $level): LtExtensionResult
    {
        if ($level === SignatureLevel::B) {
            return new LtExtensionResult(SignatureLevel::B);
        }
        if ($level === SignatureLevel::LTA) {
            throw new SigningException('LtExtender raises a signature to T or LT. The archive timestamp of LTA is added on top of LT by LtaExtender, or by SigningService, which does both');
        }

        $unsigned = $this->unsignedSignatureProperties($document, $signature);
        $timestamp = $this->addTimestamp($document, $signature, $unsigned);
        if ($level === SignatureLevel::T) {
            return new LtExtensionResult(SignatureLevel::T, $timestamp->genTime());
        }

        $warnings = [];
        $issuer = $this->chain($signer, $timestamp->genTime())->issuerOfLeaf();
        try {
            $ocspAnchors = $this->trustStore->anchors(ServiceType::ocspTypes());
        } catch (TrustedListException $e) {
            throw self::listsUnavailable($e);
        }
        $trustedResponders = array_map(static fn($anchor): Certificate => $anchor->certificate, $ocspAnchors);

        try {
            $ocsp = $this->ocspClient->fetch($signer, $issuer, array_values($trustedResponders));
        } catch (OcspException $e) {
            throw new SigningException('Could not obtain a valid OCSP response for the signature: ' . $e->getMessage(), 0, $e);
        }

        $producedAt = $ocsp->verification->producedAt();
        $delay = $producedAt->getTimestamp() - $timestamp->genTime()->getTimestamp();
        if ($delay < 0) {
            throw new SigningException(\sprintf('The OCSP response was produced %d seconds before the timestamp; the signature would be rejected', -$delay));
        }
        if ($delay > self::OCSP_DELAY_WARNING_SECONDS) {
            $warnings[] = \sprintf('The OCSP response was produced %d seconds after the timestamp; validators warn beyond %d', $delay, self::OCSP_DELAY_WARNING_SECONDS);
        }

        // CertificateValues: the signer's chain, the TSA and the OCSP responder,
        // so the signature can be validated years later without the network.
        $certificates = [
            ...$this->chainOf($signer, $timestamp->genTime()),
            $ocsp->verification->responder,
            ...$ocsp->verification->basic->certificates(),
        ];
        foreach ($this->timestampCertificates($timestamp) as $certificate) {
            $certificates[] = $certificate;
        }
        $this->addCertificateValues($document, $unsigned, $certificates, $signer);
        $this->addRevocationValues($document, $unsigned, $ocsp->der());

        return new LtExtensionResult(SignatureLevel::LT, $timestamp->genTime(), $producedAt, $warnings);
    }

    /**
     * Refuse a signer whose certificate does not chain to a trusted CA at the
     * given moment, before anything is spent on the signature.
     *
     * @throws SigningException carrying the ChainBuildingException, or the TrustedListException of lists that could not be loaded
     */
    public function requireTrustedSigner(Certificate $signer, \DateTimeInterface $at): void
    {
        $this->chain($signer, $at);
    }

    private function addTimestamp(SignatureDocument $document, \DOMElement $signature, \DOMElement $unsigned): \Allkiri\Crypto\Tsp\TimestampToken
    {
        $signatureValue = Xml::element($document->xpath(), 'ds:SignatureValue', $signature)
            ?? throw new SignatureStructureException('The signature has no ds:SignatureValue to timestamp');
        // XAdES timestamps the canonicalised ds:SignatureValue element, tag and all.
        $canonical = $this->canonicalizer->canonicalize($signatureValue, Ns::C14N_EXC);
        try {
            $result = $this->tspClient->timestamp($canonical);
        } catch (TimestampException $e) {
            throw new SigningException('Could not obtain a valid timestamp for the signature: ' . $e->getMessage(), 0, $e);
        }

        $dom = $document->document();
        $id = 'TS-' . $signature->getAttribute('Id');
        $element = $dom->createElementNS(Ns::XADES, 'xades:SignatureTimeStamp');
        $element->setAttribute('Id', $id);
        // DSS refuses to verify a timestamp whose canonicalization is unstated.
        $method = $dom->createElementNS(Ns::DS, 'ds:CanonicalizationMethod');
        $method->setAttribute('Algorithm', Ns::C14N_EXC);
        $element->appendChild($method);
        $encapsulated = $dom->createElementNS(Ns::XADES, 'xades:EncapsulatedTimeStamp', base64_encode($result->token->der()));
        $encapsulated->setAttribute('Id', 'E' . $id);
        $element->appendChild($encapsulated);
        $unsigned->appendChild($element);

        return $result->token;
    }

    /**
     * @param list<Certificate> $certificates
     */
    private function addCertificateValues(SignatureDocument $document, \DOMElement $unsigned, array $certificates, Certificate $signer): void
    {
        $seen = [$signer->fingerprint() => true]; // the signer is already in ds:KeyInfo
        $unique = [];
        foreach ($certificates as $certificate) {
            $fingerprint = $certificate->fingerprint();
            if (!isset($seen[$fingerprint])) {
                $seen[$fingerprint] = true;
                $unique[] = $certificate;
            }
        }
        if ($unique === []) {
            return;
        }

        $dom = $document->document();
        $values = $dom->createElementNS(Ns::XADES, 'xades:CertificateValues');
        foreach ($unique as $certificate) {
            $values->appendChild($dom->createElementNS(Ns::XADES, 'xades:EncapsulatedX509Certificate', $certificate->base64()));
        }
        $unsigned->appendChild($values);
    }

    private function addRevocationValues(SignatureDocument $document, \DOMElement $unsigned, string $ocspDer): void
    {
        $dom = $document->document();
        $revocation = $dom->createElementNS(Ns::XADES, 'xades:RevocationValues');
        $ocspValues = $dom->createElementNS(Ns::XADES, 'xades:OCSPValues');
        $ocspValues->appendChild($dom->createElementNS(Ns::XADES, 'xades:EncapsulatedOCSPValue', base64_encode($ocspDer)));
        $revocation->appendChild($ocspValues);
        $unsigned->appendChild($revocation);
    }

    private function unsignedSignatureProperties(SignatureDocument $document, \DOMElement $signature): \DOMElement
    {
        $xpath = $document->xpath();
        $existing = Xml::element($xpath, 'ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties', $signature);
        if ($existing !== null) {
            return $existing;
        }
        $qualifying = Xml::element($xpath, 'ds:Object/xades:QualifyingProperties', $signature)
            ?? throw new SignatureStructureException('The signature has no xades:QualifyingProperties');

        $dom = $document->document();
        $unsignedProperties = $dom->createElementNS(Ns::XADES, 'xades:UnsignedProperties');
        $unsigned = $dom->createElementNS(Ns::XADES, 'xades:UnsignedSignatureProperties');
        $unsignedProperties->appendChild($unsigned);
        $qualifying->appendChild($unsignedProperties);

        return $unsigned;
    }

    private function chain(Certificate $signer, \DateTimeInterface $at): CertificateChain
    {
        try {
            return $this->chainBuilder->build($signer, [], $at, ServiceType::caTypes());
        } catch (ChainBuildingException $e) {
            throw new SigningException(\sprintf('The signer\'s certificate does not chain to a trusted CA: %s', $e->getMessage()), 0, $e);
        } catch (TrustedListException $e) {
            throw self::listsUnavailable($e);
        }
    }

    private static function listsUnavailable(TrustedListException $e): SigningException
    {
        return new SigningException('The trusted lists the signature is checked against could not be loaded: ' . $e->getMessage(), 0, $e);
    }

    /**
     * @return list<Certificate>
     */
    private function chainOf(Certificate $signer, \DateTimeImmutable $at): array
    {
        try {
            return $this->chainBuilder->build($signer, [], $at, ServiceType::caTypes())->caCertificates();
        } catch (ChainBuildingException|TrustedListException) {
            return [];
        }
    }

    /**
     * @return list<Certificate>
     */
    private function timestampCertificates(\Allkiri\Crypto\Tsp\TimestampToken $token): array
    {
        $certificates = $token->signedData()->certificates();
        $tsa = $certificates[0] ?? null;
        if ($tsa === null) {
            return [];
        }

        try {
            return [...$certificates, ...$this->chainBuilder->build($tsa, $certificates, $token->genTime(), ServiceType::tsaTypes())->caCertificates()];
        } catch (ChainBuildingException|TrustedListException) {
            return $certificates;
        }
    }
}
