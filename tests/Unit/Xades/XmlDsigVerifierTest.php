<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Xades;

use Allkiri\Xades\Dsig\ArrayReferenceResolver;
use Allkiri\Xades\Dsig\Canonicalizer;
use Allkiri\Xades\Dsig\XmlDsigVerifier;
use Allkiri\Xades\Ns;
use Allkiri\Xades\SignatureDocument;
use Allkiri\Xades\SignatureStructureException;
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
                self::assertSame(Ns::C14N_EXC, $result->canonicalizationMethod, $name);
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

    public function testEnvelopedSignatureOfTheEstonianTestTrustedList(): void
    {
        $document = SignatureDocument::parse((string) file_get_contents(self::FIXTURES . 'captured/test-tl-EE_T.xml'));
        $signatures = $document->signatures();
        self::assertCount(1, $signatures);

        $result = (new XmlDsigVerifier())->verify($signatures[0], new ArrayReferenceResolver([]));

        self::assertSame([], $result->problems);
        self::assertTrue($result->isValid(), 'the trusted list signature verifies');
        self::assertSame('Test TSL', $result->certificate?->commonName());
        self::assertSame(Ns::C14N_EXC, $result->canonicalizationMethod);
        $enveloped = $result->reference('');
        self::assertNotNull($enveloped);
        self::assertContains(Ns::TRANSFORM_ENVELOPED, $enveloped->transforms);
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

        self::assertTrue(Canonicalizer::supports(Ns::C14N_EXC));
        self::assertTrue(Canonicalizer::supports(Ns::C14N_10));
        self::assertFalse(Canonicalizer::supports(Ns::C14N_11));

        // Exclusive c14n drops namespaces the subtree does not use; inclusive keeps them.
        self::assertSame('<c xmlns:a="urn:a" a:x="1">  text  </c>', $canonicalizer->canonicalize($child, Ns::C14N_EXC));
        self::assertStringContainsString('xmlns:unused="urn:u"', $canonicalizer->canonicalize($child, Ns::C14N_10));
        self::assertStringContainsString('<!-- note -->', $canonicalizer->canonicalize($element, Ns::C14N_EXC_WITH_COMMENTS));
        self::assertStringNotContainsString('<!-- note -->', $canonicalizer->canonicalize($element, Ns::C14N_EXC));

        $this->expectException(\Allkiri\Xades\CanonicalizationException::class);
        $canonicalizer->canonicalize($element, Ns::C14N_11);
    }

    public function testDocumentLoadingRefusesDoctypesAndMalformedXml(): void
    {
        try {
            SignatureDocument::parse('<!DOCTYPE r [<!ENTITY x "y">]><r>&x;</r>');
            self::fail('DOCTYPE accepted');
        } catch (SignatureStructureException $e) {
            self::assertStringContainsString('DOCTYPE', $e->getMessage());
        }
        try {
            SignatureDocument::parse('<r><unclosed></r>');
            self::fail('malformed XML accepted');
        } catch (SignatureStructureException $e) {
            self::assertStringContainsString('well-formed', $e->getMessage());
        }

        $this->expectException(SignatureStructureException::class);
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
