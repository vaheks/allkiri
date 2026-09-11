<?php

declare(strict_types=1);

namespace Allkiri\Xades\Dsig;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\CertificateException;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\PublicKeyVerifier;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Xades\CanonicalizationException;
use Allkiri\Xades\Ns;

/**
 * Verifies a ds:Signature element: every reference digest (same-document
 * references with enveloped and canonicalization transforms, external ones
 * through a resolver) and the signature over the canonicalised SignedInfo.
 *
 * Reports rather than throws: a bad signature is data, not an error.
 */
final class XmlDsigVerifier
{
    public function __construct(
        private readonly Canonicalizer $canonicalizer = new Canonicalizer(),
        private readonly PublicKeyVerifier $verifier = new PublicKeyVerifier(),
    ) {}

    /**
     * @param Certificate|null $certificate the signer; taken from ds:KeyInfo when null
     */
    public function verify(\DOMElement $signature, ReferenceResolver $resolver, ?Certificate $certificate = null): DsigVerificationResult
    {
        $xpath = Xml::xpath($signature);
        $problems = [];

        $signedInfo = Xml::element($xpath, 'ds:SignedInfo', $signature);
        if ($signedInfo === null) {
            return new DsigVerificationResult([], false, '', '', $certificate, '', ['ds:SignedInfo missing']);
        }
        $c14nMethod = Xml::attribute($xpath, 'ds:CanonicalizationMethod/@Algorithm', $signedInfo);
        $signatureMethod = Xml::attribute($xpath, 'ds:SignatureMethod/@Algorithm', $signedInfo);

        $references = [];
        foreach (Xml::elements($xpath, 'ds:Reference', $signedInfo) as $referenceElement) {
            $references[] = $this->verifyReference($xpath, $referenceElement, $signature, $resolver);
        }
        if ($references === []) {
            $problems[] = 'ds:SignedInfo has no references';
        }

        if ($certificate === null) {
            $certificate = $this->keyInfoCertificate($xpath, $signature, $problems);
        }

        $signedInfoCanonical = '';
        $signatureValid = false;
        try {
            $signedInfoCanonical = $this->canonicalizer->canonicalize($signedInfo, $c14nMethod);
        } catch (CanonicalizationException $e) {
            $problems[] = $e->getMessage();
        }
        $algorithm = SignatureAlgorithm::tryFromXmlUri($signatureMethod);
        if ($algorithm === null) {
            $problems[] = \sprintf('Unsupported signature method "%s"', $signatureMethod);
        }
        $signatureValue = Xml::base64($xpath, 'ds:SignatureValue', $signature);
        if ($signatureValue === null) {
            $problems[] = 'ds:SignatureValue missing or not base64';
        }
        if ($signedInfoCanonical !== '' && $algorithm !== null && $signatureValue !== null && $certificate !== null) {
            $signatureValid = $this->verifier->verify($certificate->publicKey(), $algorithm, $signedInfoCanonical, $signatureValue);
        }

        return new DsigVerificationResult($references, $signatureValid, $signatureMethod, $c14nMethod, $certificate, $signedInfoCanonical, $problems);
    }

    private function verifyReference(\DOMXPath $xpath, \DOMElement $reference, \DOMElement $signature, ReferenceResolver $resolver): ReferenceResult
    {
        $uri = $reference->getAttribute('URI');
        $digestMethod = Xml::attribute($xpath, 'ds:DigestMethod/@Algorithm', $reference);
        $transforms = [];
        $prefixLists = [];
        foreach (Xml::elements($xpath, 'ds:Transforms/ds:Transform', $reference) as $transform) {
            $transforms[] = $transform->getAttribute('Algorithm');
            $prefixList = trim(Xml::attribute($xpath, 'ec:InclusiveNamespaces/@PrefixList', $transform));
            $prefixLists[] = $prefixList === '' ? [] : self::split($prefixList);
        }
        $result = static fn(bool $resolved, bool $matches, ?string $problem = null): ReferenceResult => new ReferenceResult(
            $uri,
            $reference->getAttribute('Type'),
            $reference->getAttribute('Id'),
            $digestMethod,
            $transforms,
            $resolved,
            $matches,
            $problem,
        );

        $hash = HashAlgorithm::tryFromXmlUri($digestMethod);
        if ($hash === null) {
            return $result(false, false, \sprintf('Unsupported digest method "%s"', $digestMethod));
        }
        $expected = Xml::base64($xpath, 'ds:DigestValue', $reference);
        if ($expected === null) {
            return $result(false, false, 'ds:DigestValue missing or not base64');
        }

        try {
            $data = $this->dereference($uri, $transforms, $prefixLists, $signature, $resolver);
        } catch (CanonicalizationException $e) {
            return $result(true, false, $e->getMessage());
        }
        if ($data === null) {
            return $result(false, false, \sprintf('Reference "%s" could not be resolved', $uri));
        }

        return $result(true, hash_equals($hash->digest($data), $expected));
    }

    /**
     * @param list<string>       $transforms
     * @param list<list<string>> $prefixLists per transform
     */
    private function dereference(string $uri, array $transforms, array $prefixLists, \DOMElement $signature, ReferenceResolver $resolver): ?string
    {
        if ($uri !== '' && !str_starts_with($uri, '#')) {
            if ($transforms !== []) {
                throw new CanonicalizationException('Transforms on external references are not supported');
            }

            return $resolver->resolve(rawurldecode($uri));
        }

        $document = $signature->ownerDocument;
        if ($document === null) {
            return null;
        }
        $node = $uri === '' ? $document->documentElement : Xml::elementById($document, substr($uri, 1));
        if ($node === null) {
            return null;
        }

        $c14n = null;
        $c14nPrefixes = null;
        $enveloped = false;
        foreach ($transforms as $index => $algorithm) {
            if ($algorithm === Ns::TRANSFORM_ENVELOPED) {
                $enveloped = true;
            } elseif (Canonicalizer::supports($algorithm)) {
                $c14n = $algorithm;
                $c14nPrefixes = $prefixLists[$index] ?? null;
            } else {
                throw new CanonicalizationException(\sprintf('Unsupported transform "%s"', $algorithm));
            }
        }

        if ($enveloped) {
            $node = self::withoutSignature($document, $node, $signature);
        }

        return $this->canonicalizer->canonicalize($node, $c14n ?? Ns::C14N_10, $c14nPrefixes);
    }

    /**
     * The referenced node in a copy of the document from which this signature
     * has been removed, as the enveloped-signature transform prescribes.
     */
    private static function withoutSignature(\DOMDocument $document, \DOMNode $node, \DOMElement $signature): \DOMNode
    {
        $index = array_search($signature, self::allSignatures($document), true);
        $copy = clone $document;
        $copiedSignature = \is_int($index) ? (self::allSignatures($copy)[$index] ?? null) : null;
        $parent = $copiedSignature?->parentNode;
        if ($copiedSignature !== null && $parent !== null) {
            $parent->removeChild($copiedSignature);
        }
        if ($node === $document->documentElement) {
            return $copy->documentElement ?? $copy;
        }
        $id = $node instanceof \DOMElement ? $node->getAttribute('Id') : '';

        return ($id === '' ? null : Xml::elementById($copy, $id)) ?? $copy;
    }

    /**
     * @return list<\DOMElement>
     */
    private static function allSignatures(\DOMDocument $document): array
    {
        $signatures = [];
        foreach ($document->getElementsByTagNameNS(Ns::DS, 'Signature') as $element) {
            $signatures[] = $element;
        }

        return $signatures;
    }

    /**
     * @param list<string> $problems
     */
    private function keyInfoCertificate(\DOMXPath $xpath, \DOMElement $signature, array &$problems): ?Certificate
    {
        $base64 = Xml::text($xpath, 'ds:KeyInfo/ds:X509Data/ds:X509Certificate', $signature);
        if ($base64 === null) {
            $problems[] = 'ds:KeyInfo carries no certificate';

            return null;
        }

        try {
            return Certificate::fromBase64($base64);
        } catch (CertificateException $e) {
            $problems[] = 'ds:KeyInfo certificate is invalid: ' . $e->getMessage();

            return null;
        }
    }

    /**
     * @return list<string>
     */
    private static function split(string $whitespaceSeparated): array
    {
        $parts = preg_split('/\s+/', $whitespaceSeparated);
        if ($parts === false) {
            return [];
        }
        $strings = [];
        foreach ($parts as $part) {
            if (\is_string($part) && $part !== '') {
                $strings[] = $part;
            }
        }

        return $strings;
    }
}
