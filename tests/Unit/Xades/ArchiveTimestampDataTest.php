<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Xades;

use Allkiri\Container\AsicReader;
use Allkiri\Crypto\Tsp\TimestampToken;
use Allkiri\Signing\ContainerReferenceResolver;
use Allkiri\Xades\Lta\ArchiveTimestampData;
use Allkiri\Xades\Ns;
use Allkiri\Xades\SignatureDocument;
use Allkiri\Xades\XadesException;
use Allkiri\Xml\Dsig\Canonicalizer;
use Allkiri\Xml\Dsig\DsigNs;
use Allkiri\Xml\Dsig\ReferenceResolver;
use Allkiri\Xml\Xml;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * The archive timestamp's octet stream, checked against one digidoc4j made.
 *
 * This is the only way to know the construction is right. An archive timestamp
 * has to be verifiable years later by whatever software is current then, so
 * reproducing the imprint of a container built elsewhere is the evidence that
 * matters; our own tests agreeing with our own encoder would prove nothing.
 */
#[CoversNothing]
final class ArchiveTimestampDataTest extends TestCase
{
    private const CONTAINER = __DIR__ . '/../../fixtures/containers/valid-asice-lta.asice';

    /**
     * @return array{\DOMElement, \DOMElement, ContainerReferenceResolver, TimestampToken}
     */
    private static function fixture(): array
    {
        $container = (new AsicReader())->read((string) file_get_contents(self::CONTAINER));
        $signatureFile = $container->signatureFiles[0];
        $document = SignatureDocument::parse($signatureFile->xml);
        $signature = $document->signatures()[0];

        $xpath = $document->xpath();
        $archive = Xml::element($xpath, './/xadesv141:ArchiveTimeStamp', $signature);
        self::assertNotNull($archive, 'the fixture should carry an archive timestamp');

        $encoded = Xml::base64($xpath, './/xades:EncapsulatedTimeStamp', $archive);
        self::assertIsString($encoded);

        return [$signature, $archive, new ContainerReferenceResolver($container), TimestampToken::fromDer($encoded)];
    }

    private static function xpathOf(\DOMElement $signature): \DOMXPath
    {
        $document = $signature->ownerDocument;
        self::assertNotNull($document);

        return Xml::xpath($document, Ns::PREFIXES);
    }

    /**
     * The gate: our octet stream digests to exactly what digidoc4j's timestamp
     * authority was asked to stamp.
     */
    public function testTheImprintMatchesTheOneDigidoc4jProduced(): void
    {
        [$signature, $archive, $resolver, $token] = self::fixture();

        $data = (new ArchiveTimestampData())->forExistingTimestamp($signature, $archive, $resolver);

        $tstInfo = $token->tstInfo();
        self::assertSame('2.16.840.1.101.3.4.2.1', $tstInfo->hashAlgorithmOid, 'the fixture stamps a SHA-256 imprint');
        self::assertSame(
            bin2hex($tstInfo->messageImprint),
            bin2hex(hash('sha256', $data, true)),
        );
    }

    /**
     * The reference covering SignedProperties is part of what is stamped.
     * Leaving it out is the mistake the clause guards against by saying
     * "including", and it produces a stream that looks perfectly plausible.
     */
    public function testTheSignedPropertiesReferenceIsPartOfWhatIsStamped(): void
    {
        [$signature, $archive, $resolver] = self::fixture();
        $data = (new ArchiveTimestampData())->forExistingTimestamp($signature, $archive, $resolver);

        $properties = Xml::element(self::xpathOf($signature), './/xades:SignedProperties', $signature);
        self::assertNotNull($properties);

        self::assertStringContainsString(
            (new Canonicalizer())->canonicalize($properties, DsigNs::C14N_EXC),
            $data,
        );
    }

    /**
     * Everything the earlier timestamp and the revocation data are made of is
     * stamped too, which is the point of an archive timestamp.
     */
    public function testTheEarlierUnsignedPropertiesAreStamped(): void
    {
        [$signature, $archive, $resolver] = self::fixture();
        $data = (new ArchiveTimestampData())->forExistingTimestamp($signature, $archive, $resolver);

        $xpath = self::xpathOf($signature);
        $canonicalizer = new Canonicalizer();

        foreach (['xades:SignatureTimeStamp', 'xades:CertificateValues', 'xades:RevocationValues'] as $name) {
            $element = Xml::element($xpath, './/' . $name, $signature);
            self::assertNotNull($element, $name . ' should be in the fixture');
            self::assertStringContainsString(
                $canonicalizer->canonicalize($element, DsigNs::C14N_EXC),
                $data,
                $name . ' should be covered by the archive timestamp',
            );
        }
    }

    /**
     * The archive timestamp does not stamp itself.
     */
    public function testTheArchiveTimestampIsNotPartOfItsOwnStream(): void
    {
        [$signature, $archive, $resolver] = self::fixture();
        $data = (new ArchiveTimestampData())->forExistingTimestamp($signature, $archive, $resolver);

        $canonical = (new Canonicalizer())->canonicalize($archive, DsigNs::C14N_EXC);

        self::assertStringNotContainsString($canonical, $data);
    }

    public function testTheDeclaredCanonicalizationIsUsed(): void
    {
        [, $archive] = self::fixture();

        self::assertSame(DsigNs::C14N_EXC, ArchiveTimestampData::canonicalizationOf($archive));
    }

    /**
     * XML-DSig's default is inclusive canonicalisation, so an archive timestamp
     * that says nothing means inclusive, not the exclusive everything Estonian
     * happens to use.
     */
    public function testAnUnstatedCanonicalizationMeansTheXmlDsigDefault(): void
    {
        $document = new \DOMDocument();
        $element = $document->createElementNS(Ns::XADES141, 'xadesv141:ArchiveTimeStamp');

        self::assertSame(DsigNs::C14N_10, ArchiveTimestampData::canonicalizationOf($element));
    }

    /**
     * A data file the container no longer holds makes the stream
     * unreconstructable, and saying so beats stamping something incomplete.
     */
    public function testAMissingDataFileIsReported(): void
    {
        [$signature, $archive] = self::fixture();

        $empty = new class implements ReferenceResolver {
            public function resolve(string $uri): ?string
            {
                return null;
            }
        };

        $this->expectException(XadesException::class);

        (new ArchiveTimestampData())->forExistingTimestamp($signature, $archive, $empty);
    }
}
