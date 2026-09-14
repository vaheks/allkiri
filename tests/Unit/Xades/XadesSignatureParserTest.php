<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Xades;

use Allkiri\Container\AsicReader;
use Allkiri\Tests\Support\Xades\SignatureWrapping;
use Allkiri\Xades\Model\XadesSignatureParser;
use Allkiri\Xades\SignatureDocument;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The read model describes what the signature commits to, and nothing that was
 * placed next to it.
 */
#[CoversNothing]
final class XadesSignatureParserTest extends TestCase
{
    private const CONTAINER = __DIR__ . '/../../fixtures/containers/valid-asice.asice';
    private const SIGNED_PROPERTIES_REFERENCE = '#xades-id-8c2a30729f251c6cb8336844b97f0657';

    public function testAGenuineSignatureHasItsSignedPropertiesRead(): void
    {
        $signature = (new XadesSignatureParser())->parse(self::signature(self::signatureXml()));

        self::assertSame('2018-11-23T12:24:04+00:00', $signature->signingTime?->format(DATE_ATOM));
        self::assertNotSame([], $signature->signingCertificateReferences);
        self::assertNotSame([], $signature->dataObjectFormats);
        self::assertNull($signature->unboundSignedPropertiesReference);
        self::assertSame([], $signature->warnings);
    }

    /**
     * @return iterable<string, array{\Closure(string): string}>
     */
    public static function wrappings(): iterable
    {
        yield 'a copy carrying the same Id' => [static fn(string $xml): string => SignatureWrapping::duplicateId($xml)];
        yield 'a copy carrying the Id, the original renamed' => [static fn(string $xml): string => SignatureWrapping::renamedOriginal($xml)];
    }

    /**
     * @param \Closure(string): string $wrap
     */
    #[DataProvider('wrappings')]
    public function testSignedPropertiesTheReferenceDoesNotCoverAreNotRead(\Closure $wrap): void
    {
        $signature = (new XadesSignatureParser())->parse(self::signature($wrap(self::signatureXml())));

        self::assertNull($signature->signingTime, 'the altered signing time must not be read');
        self::assertSame([], $signature->signingCertificateReferences);
        self::assertSame([], $signature->dataObjectFormats);
        self::assertSame(self::SIGNED_PROPERTIES_REFERENCE, $signature->unboundSignedPropertiesReference);
        self::assertStringContainsString(self::SIGNED_PROPERTIES_REFERENCE, implode("\n", $signature->warnings));
    }

    private static function signatureXml(): string
    {
        return (new AsicReader())->readFile(self::CONTAINER)->signatureFiles[0]->xml;
    }

    private static function signature(string $xml): \DOMElement
    {
        return SignatureDocument::parse($xml)->signatures()[0] ?? self::fail('The document has no ds:Signature');
    }
}
