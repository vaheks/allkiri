<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Xml;

use Allkiri\Xades\SignatureStructureException;
use Allkiri\Xades\XadesException;
use Allkiri\Xml\Dsig\CanonicalizationException;
use Allkiri\Xml\InvalidXmlException;
use Allkiri\Xml\Xml;
use Allkiri\Xml\XmlException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Every untrusted XML document passes through here: signature files and
 * manifests from uploaded containers, and trusted lists from the network. A
 * DTD is refused whatever encoding hides it, so none of them can expand
 * entities.
 */
#[CoversClass(Xml::class)]
final class XmlTest extends TestCase
{
    private const WITH_DTD = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><r>&b;</r>';
    private const WITHOUT_DTD = '<?xml version="1.0" encoding="UTF-16"?><r>tere</r>';

    /**
     * @return iterable<string, array{string}>
     */
    public static function byteOrders(): iterable
    {
        yield 'UTF-16LE' => ['UTF-16LE'];
        yield 'UTF-16BE' => ['UTF-16BE'];
    }

    #[DataProvider('byteOrders')]
    public function testADtdInUtf16IsRefused(string $encoding): void
    {
        $xml = self::utf16(self::WITH_DTD, $encoding);
        self::assertSame(0, preg_match('/<!DOCTYPE/i', $xml), 'the zero bytes hide the DOCTYPE from a byte search');

        $this->expectException(InvalidXmlException::class);
        $this->expectExceptionMessage('DOCTYPE');

        Xml::load($xml);
    }

    #[DataProvider('byteOrders')]
    public function testUtf16WithoutADtdStillParses(string $encoding): void
    {
        $document = Xml::load(self::utf16(self::WITHOUT_DTD, $encoding));

        self::assertSame('tere', $document->documentElement?->textContent);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function notXml(): iterable
    {
        yield 'empty' => ['', 'Empty'];
        yield 'not well-formed' => ['<r><unclosed></r>', 'not well-formed'];
        yield 'a lower-case doctype' => ['<!doctype r><r/>', 'DOCTYPE'];
    }

    #[DataProvider('notXml')]
    public function testBytesThatAreNotXmlAreRefused(string $xml, string $message): void
    {
        $this->expectException(InvalidXmlException::class);
        $this->expectExceptionMessage($message);

        Xml::load($xml);
    }

    public function testAnXPathSearchesWithThePrefixesItIsGiven(): void
    {
        $document = Xml::load('<m:a xmlns:m="urn:allkiri:test"><m:b>tere</m:b></m:a>');
        $root = $document->documentElement ?? throw new \LogicException('The test document has no root');

        self::assertSame('tere', Xml::text(Xml::xpath($document, ['t' => 'urn:allkiri:test']), 't:b', $root));
    }

    /**
     * @return iterable<string, array{class-string<\Throwable>, bool}>
     */
    public static function documentFailures(): iterable
    {
        yield 'not XML' => [InvalidXmlException::class, false];
        yield 'a canonicalisation that cannot be run' => [CanonicalizationException::class, false];
        yield 'a XAdES failure' => [XadesException::class, true];
        yield 'a signature without the structure it needs' => [SignatureStructureException::class, true];
    }

    /**
     * Whether the XML or the XAdES inside it is at fault, a caller catching
     * XmlException catches it. Only the XAdES layer's own are XadesExceptions.
     *
     * @param class-string<\Throwable> $class
     */
    #[DataProvider('documentFailures')]
    public function testEveryFailureOfADocumentIsAnXmlException(string $class, bool $xades): void
    {
        self::assertTrue(is_a($class, XmlException::class, true), $class . ' is not an XmlException');
        self::assertSame($xades, is_a($class, XadesException::class, true), $class . ($xades ? ' is not' : ' is') . ' a XadesException');
    }

    private static function utf16(string $xml, string $encoding): string
    {
        $byteOrderMark = $encoding === 'UTF-16LE' ? "\xFF\xFE" : "\xFE\xFF";

        return $byteOrderMark . mb_convert_encoding($xml, $encoding, 'UTF-8');
    }
}
