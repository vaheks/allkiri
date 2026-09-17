<?php

declare(strict_types=1);

namespace Allkiri\Trust\TrustedList;

use Allkiri\Crypto\Certificate;
use Allkiri\Xml\Dsig\ArrayReferenceResolver;
use Allkiri\Xml\Dsig\DsigNs;
use Allkiri\Xml\Dsig\DsigVerificationResult;
use Allkiri\Xml\Dsig\XmlDsigVerifier;
use Allkiri\Xml\InvalidXmlException;
use Allkiri\Xml\Xml;

/**
 * Checks the enveloped XML signature of a trusted list against the
 * certificates that are allowed to sign it.
 *
 * Which certificates those are is the caller's decision: for the Estonian
 * test list they are pinned in configuration; in production they come from
 * the pointer in the EU list of trusted lists.
 *
 * A valid signature is not enough on its own: it has to be over the list that
 * is read. The parser reads the root element, so the signature must sit
 * directly under it and its one content reference must cover it, with the
 * enveloped-signature transform. Otherwise a genuine list that signs its root
 * by Id could be nested inside a forged one and still verify, as DSS also
 * guards against.
 *
 * @internal
 */
final class TrustedListVerifier
{
    private const TYPE_SIGNED_PROPERTIES = 'http://uri.etsi.org/01903#SignedProperties';

    public function __construct(private readonly XmlDsigVerifier $verifier = new XmlDsigVerifier()) {}

    /**
     * @param list<Certificate> $allowedSigners
     *
     *
     * @throws TrustedListException
     * @return Certificate the certificate that actually signed it
     */
    public function verify(string $xml, array $allowedSigners): Certificate
    {
        if ($allowedSigners === []) {
            throw new TrustedListException(TrustedListException::REASON_NO_PINS, 'No certificates are configured as allowed signers of this trusted list');
        }

        try {
            $document = Xml::load($xml);
        } catch (InvalidXmlException $e) {
            throw new TrustedListException(TrustedListException::REASON_MALFORMED, 'Trusted list is not well-formed XML: ' . $e->getMessage(), $e);
        }
        $root = $document->documentElement;
        if ($root === null) {
            throw new TrustedListException(TrustedListException::REASON_MALFORMED, 'Trusted list has no root element');
        }
        $signatures = [];
        foreach ($root->childNodes as $child) {
            if ($child instanceof \DOMElement && $child->namespaceURI === DsigNs::DS && $child->localName === 'Signature') {
                $signatures[] = $child;
            }
        }
        if ($signatures === []) {
            throw new TrustedListException(TrustedListException::REASON_SIGNATURE, 'Trusted list is not signed: its root element has no signature');
        }
        if (\count($signatures) > 1) {
            throw new TrustedListException(TrustedListException::REASON_SIGNATURE, 'Trusted list carries more than one signature');
        }
        $signature = $signatures[0];

        $result = $this->verifier->verify($signature, new ArrayReferenceResolver([]));
        self::requireWholeList($result, $root);
        $signer = $result->certificate;
        if ($signer === null) {
            throw new TrustedListException(TrustedListException::REASON_SIGNATURE, 'Trusted list signature carries no certificate');
        }
        $allowed = false;
        foreach ($allowedSigners as $candidate) {
            if ($candidate->equals($signer)) {
                $allowed = true;
                break;
            }
        }
        if (!$allowed) {
            throw new TrustedListException(TrustedListException::REASON_SIGNER_NOT_ALLOWED, \sprintf('Trusted list is signed by "%s", which is not an allowed signer', $signer->subjectDn()));
        }
        if (!$result->isValid()) {
            $detail = $result->problems === [] ? 'the signature or a reference digest does not match' : implode('; ', $result->problems);

            throw new TrustedListException(TrustedListException::REASON_SIGNATURE, 'Trusted list signature does not verify: ' . $detail);
        }

        return $signer;
    }

    /**
     * The one reference that is not XAdES's signed properties must be to the
     * root: the whole document, or the root's own Id, with the signature
     * itself taken out.
     *
     * @throws TrustedListException
     */
    private static function requireWholeList(DsigVerificationResult $result, \DOMElement $root): void
    {
        $content = [];
        foreach ($result->references as $reference) {
            if ($reference->type !== self::TYPE_SIGNED_PROPERTIES) {
                $content[] = $reference;
            }
        }
        $rootId = $root->getAttribute('Id');
        $reference = \count($content) === 1 ? $content[0] : null;
        $coversRoot = $reference !== null
            && ($reference->uri === '' || ($rootId !== '' && $reference->uri === '#' . $rootId))
            && \in_array(DsigNs::TRANSFORM_ENVELOPED, $reference->transforms, true);
        if (!$coversRoot) {
            throw new TrustedListException(TrustedListException::REASON_SIGNATURE, 'Trusted list signature does not cover the whole list');
        }
    }
}
