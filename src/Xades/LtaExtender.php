<?php

declare(strict_types=1);

namespace Allkiri\Xades;

use Allkiri\Crypto\Tsp\TimestampToken;
use Allkiri\Crypto\Tsp\TspClient;
use Allkiri\Signing\SignatureLevel;
use Allkiri\Xades\Dsig\ReferenceResolver;
use Allkiri\Xades\Dsig\Xml;
use Allkiri\Xades\Lta\ArchiveTimestampData;
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
    public function __construct(
        private readonly TspClient $tspClient,
        private readonly ArchiveTimestampData $data = new ArchiveTimestampData(),
        private readonly ?LoggerInterface $logger = null,
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

        $stream = $this->data->forNewTimestamp($signature, $resolver, Ns::C14N_EXC);
        $stamped = $this->tspClient->timestamp($stream);
        $token = $stamped->token;

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

        $canonicalization = $dom->createElementNS(Ns::DS, 'ds:CanonicalizationMethod');
        $canonicalization->setAttribute('Algorithm', Ns::C14N_EXC);
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
