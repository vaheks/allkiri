<?php

declare(strict_types=1);

namespace Allkiri\Trust\TrustedList;

use Allkiri\Crypto\Certificate;
use Allkiri\Xades\Dsig\ArrayReferenceResolver;
use Allkiri\Xades\Dsig\XmlDsigVerifier;
use Allkiri\Xades\SignatureDocument;
use Allkiri\Xades\SignatureStructureException;

/**
 * Checks the enveloped XML signature of a trusted list against the
 * certificates that are allowed to sign it.
 *
 * Which certificates those are is the caller's decision: for the Estonian
 * test list they are pinned in configuration; in production they come from
 * the pointer in the EU list of trusted lists.
 */
final class TrustedListVerifier
{
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
            $document = SignatureDocument::parse($xml);
        } catch (SignatureStructureException $e) {
            throw new TrustedListException(TrustedListException::REASON_MALFORMED, 'Trusted list is not well-formed XML: ' . $e->getMessage(), $e);
        }
        $signatures = $document->signatures();
        if ($signatures === []) {
            throw new TrustedListException(TrustedListException::REASON_SIGNATURE, 'Trusted list is not signed');
        }

        $result = $this->verifier->verify($signatures[0], new ArrayReferenceResolver([]));
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
}
