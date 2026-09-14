<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Xades;

use Allkiri\Xades\SignatureDocument;
use Allkiri\Xades\SignatureStructureException;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Every untrusted XML document passes through here: signature files and
 * manifests from uploaded containers, and trusted lists from the network. A
 * DTD is refused whatever encoding hides it, so none of them can expand
 * entities.
 */
#[CoversNothing]
final class SignatureDocumentTest extends TestCase
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

        $this->expectException(SignatureStructureException::class);
        $this->expectExceptionMessage('DOCTYPE');

        SignatureDocument::parse($xml);
    }

    #[DataProvider('byteOrders')]
    public function testUtf16WithoutADtdStillParses(string $encoding): void
    {
        $document = SignatureDocument::parse(self::utf16(self::WITHOUT_DTD, $encoding));

        self::assertSame('tere', $document->document()->documentElement?->textContent);
    }

    private static function utf16(string $xml, string $encoding): string
    {
        $byteOrderMark = $encoding === 'UTF-16LE' ? "\xFF\xFE" : "\xFE\xFF";

        return $byteOrderMark . mb_convert_encoding($xml, $encoding, 'UTF-8');
    }
}
