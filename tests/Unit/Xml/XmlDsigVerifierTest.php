<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Xml;

use Allkiri\Container\AsicReader;
use Allkiri\Signing\ContainerReferenceResolver;
use Allkiri\Tests\Support\Xades\SignatureWrapping;
use Allkiri\Xades\SignatureDocument;
use Allkiri\Xml\Dsig\ArrayReferenceResolver;
use Allkiri\Xml\Dsig\Canonicalizer;
use Allkiri\Xml\Dsig\DsigNs;
use Allkiri\Xml\Dsig\XmlDsigVerifier;
use Allkiri\Xml\InvalidXmlException;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The canonicalisation gate: signatures made by digidoc4j and by RIA's own
 * trusted-list tooling must verify with our verifier, byte for byte.
 */
#[CoversNothing]
final class XmlDsigVerifierTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/../../fixtures/';

    /**
     * @return iterable<string, array{string, string, int}>
     */
    public static function containers(): iterable
    {
        yield 'ECDSA P-384, ESTEID2018' => ['valid-asice-esteid2018.asice', 'ecdsa-sha384', 1];
        yield 'RSA 2048, ESTEID-SK 2015' => ['valid-asice.asice', 'rsa-sha256', 1];
        yield 'LTA with an archive timestamp' => ['valid-asice-lta.asice', 'rsa-sha256', 1];
        yield 'OCSP 15 minutes after the timestamp' => ['EE_LT_sig_OCSP_15m6s_after_TS.asice', 'ecdsa-sha384', 1];
        yield 'LT without CertificateValues' => ['NoAdditionalCertificates_LT.asice', 'ecdsa-sha256', 1];
        yield 'two signature files' => ['2_signatures_duplicate_id.asice', 'ecdsa-sha384', 2];
    }

    #[DataProvider('containers')]
    public function testDigidoc4jContainersVerify(string $file, string $expectedAlgorithm, int $expectedSignatures): void
    {
        $zip = new \ZipArchive();
        self::assertTrue($zip->open(self::FIXTURES . 'containers/' . $file) === true);
        $dataFiles = [];
        $signatureFiles = [];
        for ($i = 0; $i < $zip->numFiles; ++$i) {
            $name = (string) $zip->getNameIndex($i);
            $content = (string) $zip->getFromIndex($i);
            if (preg_match('#^META-INF/signatures\d*\.xml$#', $name) === 1) {
                $signatureFiles[$name] = $content;
            } elseif ($name !== 'mimetype' && !str_starts_with($name, 'META-INF/')) {
                $dataFiles[$name] = $content;
            }
        }
        $zip->close();

        self::assertCount($expectedSignatures, $signatureFiles);
        $resolver = new ArrayReferenceResolver($dataFiles);
        $verifier = new XmlDsigVerifier();
        $verified = 0;

        foreach ($signatureFiles as $name => $xml) {
            $document = SignatureDocument::parse($xml);
            foreach ($document->signatures() as $signature) {
                $result = $verifier->verify($signature, $resolver);

                self::assertSame([], $result->problems, $name);
                self::assertNotNull($result->certificate, $name);
                self::assertStringContainsString($expectedAlgorithm, $result->signatureMethod, $name);
                self::assertSame(DsigNs::C14N_EXC, $result->canonicalizationMethod, $name);
                self::assertCount(2, $result->references, $name . ': one data file plus SignedProperties');
                foreach ($result->references as $reference) {
                    self::assertTrue($reference->resolved, $name . ' ' . $reference->uri);
                    self::assertTrue($reference->digestMatches, $name . ' ' . $reference->uri . ' digest');
                }
                self::assertTrue($result->signatureValid, $name . ': SignatureValue');
                self::assertTrue($result->isValid(), $name);
                ++$verified;
            }
        }
        self::assertSame($expectedSignatures, $verified);
    }

    public function testTamperedDataFileAndSignatureAreDetected(): void
    {
        $zip = new \ZipArchive();
        $zip->open(self::FIXTURES . 'containers/valid-asice-esteid2018.asice');
        $xml = (string) $zip->getFromName('META-INF/signatures0.xml');
        $content = (string) $zip->getFromName('test.txt');
        $zip->close();

        $verifier = new XmlDsigVerifier();
        $signature = SignatureDocument::parse($xml)->signatures()[0];

        $tampered = $verifier->verify($signature, new ArrayReferenceResolver(['test.txt' => $content . ' extra']));
        self::assertFalse($tampered->isValid());
        self::assertTrue($tampered->signatureValid, 'the signature itself is untouched');
        self::assertFalse($tampered->reference('test.txt')?->digestMatches);

        $missing = $verifier->verify($signature, new ArrayReferenceResolver([]));
        self::assertFalse($missing->isValid());
        self::assertFalse($missing->reference('test.txt')?->resolved);

        // Flip one byte of the SignatureValue: references still match, the
        // signature no longer verifies. The new character must differ from the
        // old one, which a constant does not guarantee when the value itself is
        // random.
        $brokenXml = preg_replace_callback(
            '/(<ds:SignatureValue[^>]*>)(.)/',
            static fn(array $m): string => $m[1] . ($m[2] === 'A' ? 'B' : 'A'),
            $xml,
            1,
        );
        self::assertIsString($brokenXml);
        self::assertNotSame($xml, $brokenXml);
        $broken = SignatureDocument::parse($brokenXml);
        $result = $verifier->verify($broken->signatures()[0], new ArrayReferenceResolver(['test.txt' => $content]));
        self::assertFalse($result->signatureValid);
        self::assertTrue($result->reference('test.txt')?->digestMatches);
    }

    public function testAReferenceToAnIdThatSeveralElementsCarryIsNotFollowed(): void
    {
        $container = (new AsicReader())->readFile(self::FIXTURES . 'containers/valid-asice.asice');
        $resolver = new ContainerReferenceResolver($container);
        $verifier = new XmlDsigVerifier();
        $uri = '#xades-id-8c2a30729f251c6cb8336844b97f0657';

        $wrapped = SignatureDocument::parse(SignatureWrapping::duplicateId($container->signatureFiles[0]->xml));
        $result = $verifier->verify($wrapped->signatures()[0], $resolver);

        $reference = $result->reference($uri);
        self::assertNotNull($reference);
        self::assertTrue($reference->ambiguous);
        self::assertFalse($reference->resolved);
        self::assertStringContainsString('2 elements carry the Id "xades-id-8c2a30729f251c6cb8336844b97f0657"', (string) $reference->problem);
        self::assertFalse($result->isValid());
        self::assertTrue($result->signatureValid, 'the SignatureValue is untouched, which is what makes this dangerous');

        // With every Id unique the reference is followed as before. Telling
        // the copy from the signature's own properties is the parser's job.
        $renamed = SignatureDocument::parse(SignatureWrapping::renamedOriginal($container->signatureFiles[0]->xml));
        $reference = $verifier->verify($renamed->signatures()[0], $resolver)->reference($uri);
        self::assertNotNull($reference);
        self::assertFalse($reference->ambiguous);
        self::assertTrue($reference->isValid());
    }

    /**
     * The enveloped-signature transform removes the signature from the
     * document. A reference through it to something inside that signature, as
     * a XAdES SignedProperties is, has nothing left to point at. The verifier
     * used to digest the rest of the document instead, so the properties were
     * covered by nothing, and anyone could change them under a valid
     * signature.
     */
    public function testAnEnvelopedReferenceToWhatTheSignatureHoldsCoversNothing(): void
    {
        $keyPair = \Allkiri\Tests\Support\Pki\TestPki::signerEc256();
        $canonicalizer = new Canonicalizer();
        $build = static function (string $properties, string $digest, string $signatureValue): \DOMDocument {
            $document = new \DOMDocument();
            $document->loadXML(
                '<root><ds:Signature xmlns:ds="' . DsigNs::DS . '"><ds:SignedInfo>'
                . '<ds:CanonicalizationMethod Algorithm="' . DsigNs::C14N_EXC . '"/>'
                . '<ds:SignatureMethod Algorithm="' . \Allkiri\Crypto\SignatureAlgorithm::ES256->xmlUri() . '"/>'
                . '<ds:Reference URI="#props"><ds:Transforms>'
                . '<ds:Transform Algorithm="' . DsigNs::TRANSFORM_ENVELOPED . '"/><ds:Transform Algorithm="' . DsigNs::C14N_EXC . '"/>'
                . '</ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
                . '<ds:DigestValue>' . $digest . '</ds:DigestValue></ds:Reference></ds:SignedInfo>'
                . '<ds:SignatureValue>' . $signatureValue . '</ds:SignatureValue>'
                . '<ds:Object><Props Id="props">' . $properties . '</Props></ds:Object></ds:Signature></root>',
            );

            return $document;
        };
        // The digest the old code computed: the document with the signature
        // removed, whatever the properties said.
        $digest = base64_encode(hash('sha256', '<root></root>', true));
        $unsigned = $build('signed at noon', $digest, '');
        $signedInfo = $unsigned->getElementsByTagNameNS(DsigNs::DS, 'SignedInfo')->item(0);
        self::assertNotNull($signedInfo);
        $value = base64_encode($keyPair->privateKey->sign(\Allkiri\Crypto\SignatureAlgorithm::ES256, $canonicalizer->canonicalize($signedInfo, DsigNs::C14N_EXC)));

        foreach (['signed at noon', 'changed to midnight'] as $properties) {
            $signature = $build($properties, $digest, $value)->getElementsByTagNameNS(DsigNs::DS, 'Signature')->item(0);
            self::assertInstanceOf(\DOMElement::class, $signature);
            $result = (new XmlDsigVerifier())->verify($signature, new ArrayReferenceResolver([]), $keyPair->certificate);

            self::assertTrue($result->signatureValid, 'the signature value itself is genuine');
            self::assertFalse($result->isValid(), $properties . ' passed');
            self::assertStringContainsString('removes what it points at', (string) $result->reference('#props')?->problem);
        }
    }

    public function testEnvelopedSignatureOfTheEstonianTestTrustedList(): void
    {
        $document = SignatureDocument::parse((string) file_get_contents(self::FIXTURES . 'captured/test-tl-EE_T.xml'));
        $signatures = $document->signatures();
        self::assertCount(1, $signatures);

        $result = (new XmlDsigVerifier())->verify($signatures[0], new ArrayReferenceResolver([]));

        self::assertSame([], $result->problems);
        self::assertTrue($result->isValid(), 'the trusted list signature verifies');
        self::assertSame('Test TSL', $result->certificate?->commonName());
        self::assertSame(DsigNs::C14N_EXC, $result->canonicalizationMethod);
        $enveloped = $result->reference('');
        self::assertNotNull($enveloped);
        self::assertContains(DsigNs::TRANSFORM_ENVELOPED, $enveloped->transforms);
        self::assertTrue($enveloped->isSameDocument());
    }

    public function testTestLotlAlsoVerifies(): void
    {
        $document = SignatureDocument::parse((string) file_get_contents(self::FIXTURES . 'captured/test-lotl-tl-mp-test-EE.xml'));
        $result = (new XmlDsigVerifier())->verify($document->signatures()[0], new ArrayReferenceResolver([]));

        self::assertTrue($result->isValid());
        self::assertSame('Test TSL', $result->certificate?->commonName());
    }

    public function testCanonicalizerSupportsTheAlgorithmsWeEmitAndRejectsC14n11(): void
    {
        $canonicalizer = new Canonicalizer();
        $document = SignatureDocument::parse('<r xmlns:a="urn:a" xmlns:unused="urn:u"><c a:x="1">  text  </c><!-- note --></r>');
        $element = $document->document()->documentElement;
        self::assertNotNull($element);
        $child = $element->firstChild;
        self::assertNotNull($child);

        self::assertTrue(Canonicalizer::supports(DsigNs::C14N_EXC));
        self::assertTrue(Canonicalizer::supports(DsigNs::C14N_10));
        self::assertFalse(Canonicalizer::supports(DsigNs::C14N_11));

        // Exclusive c14n drops namespaces the subtree does not use; inclusive keeps them.
        self::assertSame('<c xmlns:a="urn:a" a:x="1">  text  </c>', $canonicalizer->canonicalize($child, DsigNs::C14N_EXC));
        self::assertStringContainsString('xmlns:unused="urn:u"', $canonicalizer->canonicalize($child, DsigNs::C14N_10));
        self::assertStringContainsString('<!-- note -->', $canonicalizer->canonicalize($element, DsigNs::C14N_EXC_WITH_COMMENTS));
        self::assertStringNotContainsString('<!-- note -->', $canonicalizer->canonicalize($element, DsigNs::C14N_EXC));

        $this->expectException(\Allkiri\Xml\Dsig\CanonicalizationException::class);
        $canonicalizer->canonicalize($element, DsigNs::C14N_11);
    }

    public function testDocumentLoadingRefusesDoctypesAndMalformedXml(): void
    {
        try {
            SignatureDocument::parse('<!DOCTYPE r [<!ENTITY x "y">]><r>&x;</r>');
            self::fail('DOCTYPE accepted');
        } catch (InvalidXmlException $e) {
            self::assertStringContainsString('DOCTYPE', $e->getMessage());
        }
        try {
            SignatureDocument::parse('<r><unclosed></r>');
            self::fail('malformed XML accepted');
        } catch (InvalidXmlException $e) {
            self::assertStringContainsString('well-formed', $e->getMessage());
        }

        $this->expectException(InvalidXmlException::class);
        SignatureDocument::parse('');
    }

    public function testDocumentSurvivesARoundTripWithItsSignatureIntact(): void
    {
        $xml = (string) file_get_contents(self::FIXTURES . 'captured/test-lotl-tl-mp-test-EE.xml');
        $document = SignatureDocument::parse($xml);

        self::assertCount(1, $document->signatures());
        self::assertNull($document->signature('no-such-id'));
        $id = $document->signatures()[0]->getAttribute('Id');
        if ($id !== '') {
            self::assertNotNull($document->signature($id));
        }

        // Serialising and re-parsing must not disturb one signed byte. saveXML()
        // may differ from the input in the XML declaration and a trailing
        // newline, so assert what matters: the signature still verifies and
        // canonicalises identically.
        $verifier = new XmlDsigVerifier();
        $resolver = new ArrayReferenceResolver([]);
        $again = SignatureDocument::parse($document->toXml());

        self::assertTrue($verifier->verify($again->signatures()[0], $resolver)->isValid());
        self::assertSame(
            $verifier->verify($document->signatures()[0], $resolver)->signedInfoCanonical,
            $verifier->verify($again->signatures()[0], $resolver)->signedInfoCanonical,
        );
    }
}
