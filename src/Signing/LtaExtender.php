<?php

declare(strict_types=1);

namespace Allkiri\Signing;

use Allkiri\Crypto\Tsp\TimestampToken;
use Allkiri\Crypto\Tsp\TimestampVerificationException;
use Allkiri\Crypto\Tsp\TspClient;
use Allkiri\Trust\ChainBuilder;
use Allkiri\Trust\ChainBuildingException;
use Allkiri\Trust\ServiceType;
use Allkiri\Xades\Lta\ArchiveTimestampData;
use Allkiri\Xades\Ns;
use Allkiri\Xades\SignatureDocument;
use Allkiri\Xades\XadesException;
use Allkiri\Xml\Dsig\DsigNs;
use Allkiri\Xml\Dsig\ReferenceResolver;
use Allkiri\Xml\Xml;
use Psr\Log\LoggerInterface;

/**
 * Raises an LT signature to LTA by adding an archive timestamp.
 *
 * The point is longevity. An LT signature is only as good as the algorithms and
 * the certificates it rests on: when SHA-256 weakens, or the timestamp
 * authority's own certificate expires, there is no longer proof that the
 * signature existed while all of it was still sound. An archive timestamp
 * re-stamps the whole assembly — the signature, the earlier timestamp, the
 * certificates and the revocation answers — so a fresh, stronger proof carries
 * the old one.
 *
 * Which means it can be applied more than once. Each new archive timestamp
 * covers every one before it, so a signature can be carried forward
 * indefinitely by stamping it again before the previous stamp weakens.
 */
final class LtaExtender
{
    /**
     * @param ChainBuilder $chainBuilder decides whether the authority of an
     *                                   archive timestamp is trusted
     */
    public function __construct(
        private readonly TspClient $tspClient,
        private readonly ChainBuilder $chainBuilder,
        private readonly ?LoggerInterface $logger = null,
        private readonly ArchiveTimestampData $data = new ArchiveTimestampData(),
    ) {}

    /**
     * Add an archive timestamp covering everything the signature holds now.
     *
     * @param ReferenceResolver $resolver supplies the data files, which are part
     *                                    of what is stamped
     *
     * @throws XadesException                           when the signature is not at LT, or what is stamped
     *                                                  cannot be reconstructed
     * @throws \Allkiri\Crypto\Tsp\TimestampException when the archive timestamp cannot be had or trusted
     * @throws \Allkiri\Trust\TrustedList\TrustedListException when the trusted lists cannot be loaded
     *
     * @internal
     */
    public function extend(SignatureDocument $document, \DOMElement $signature, ReferenceResolver $resolver): LtaExtensionResult
    {
        $xpath = $document->xpath();

        // An archive timestamp over a signature with no revocation data would
        // preserve something that was never verifiable in the first place.
        if (Xml::element($xpath, './/xades:SignatureTimeStamp', $signature) === null) {
            throw new XadesException('An archive timestamp needs a signature timestamp beneath it; extend to LT first');
        }
        if (Xml::element($xpath, './/xades:RevocationValues', $signature) === null) {
            throw new XadesException('An archive timestamp needs revocation data beneath it; extend to LT first');
        }

        $unsigned = $this->unsignedSignatureProperties($document, $signature);

        $stream = $this->data->forNewTimestamp($signature, $resolver, DsigNs::C14N_EXC);
        $stamped = $this->tspClient->timestamp($stream);
        $token = $stamped->token;
        try {
            $this->chainBuilder->build($stamped->tsaCertificate, $token->signedData()->certificates(), $token->genTime(), ServiceType::tsaTypes());
        } catch (ChainBuildingException $e) {
            throw new TimestampVerificationException(
                TimestampVerificationException::REASON_AUTHORITY_NOT_TRUSTED,
                \sprintf('The archive timestamp authority "%s" is not trusted: %s', $stamped->tsaCertificate->subjectDn(), $e->getMessage()),
                $e,
            );
        }

        $this->append($document, $unsigned, $token);

        $existing = \count(Xml::elements($xpath, './/xadesv141:ArchiveTimeStamp', $signature));
        $this->logger?->info('Added archive timestamp {n} at {time}', [
            'n' => $existing,
            'time' => $token->genTime()->format(DATE_ATOM),
        ]);

        return new LtaExtensionResult(SignatureLevel::LTA, $token->genTime(), $existing);
    }

    /**
     * Write the `xadesv141:ArchiveTimeStamp` element.
     *
     * The canonicalisation method is stated explicitly. XML-DSig's default is
     * inclusive, so a validator reading an element that says nothing would
     * reconstruct a different stream and reject the timestamp.
     */
    private function append(SignatureDocument $document, \DOMElement $unsigned, TimestampToken $token): void
    {
        $dom = $document->document();

        $archive = $dom->createElementNS(Ns::XADES141, 'xadesv141:ArchiveTimeStamp');

        $canonicalization = $dom->createElementNS(DsigNs::DS, 'ds:CanonicalizationMethod');
        $canonicalization->setAttribute('Algorithm', DsigNs::C14N_EXC);
        $archive->appendChild($canonicalization);

        $encapsulated = $dom->createElementNS(Ns::XADES, 'xades:EncapsulatedTimeStamp');
        $encapsulated->appendChild($dom->createTextNode(base64_encode($token->der())));
        $archive->appendChild($encapsulated);

        $unsigned->appendChild($archive);
    }

    private function unsignedSignatureProperties(SignatureDocument $document, \DOMElement $signature): \DOMElement
    {
        $existing = Xml::element($document->xpath(), './/xades:UnsignedSignatureProperties', $signature);
        if ($existing === null) {
            throw new XadesException('The signature has no unsigned properties, so it cannot be at LT');
        }

        return $existing;
    }
}
