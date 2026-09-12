<?php

declare(strict_types=1);

namespace Allkiri\Tests\Integration;

use Allkiri\Allkiri;
use Allkiri\Clock\SystemClock;
use Allkiri\Config\ArrayCache;
use Allkiri\Config\Environment;
use Allkiri\Trust\ListOfListsTrustStore;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustedList\ListOfListsSource;
use Allkiri\Trust\TrustedList\TrustedListLoader;
use Allkiri\Trust\TrustedList\TrustedListParser;
use Allkiri\Trust\TrustedList\TrustedListPointer;

/**
 * Production trust, end to end against the live services.
 *
 * This is the one part of the library whose correctness cannot be established
 * offline: the certificates that may sign the European list of trusted lists
 * are shipped with allkiri, and if the Commission publishes a new set without
 * anyone noticing, production stops trusting anything. A nightly failure here
 * is that warning.
 */
final class ListOfListsLiveTest extends IntegrationTestCase
{
    private function loader(): TrustedListLoader
    {
        return new TrustedListLoader(self::http(60), new ArrayCache(), clock: new SystemClock());
    }

    /**
     * The whole point: the live list is signed by one of the certificates we
     * ship, which we took from the Official Journal.
     */
    public function testTheLiveListOfListsIsSignedByACertificateWeShip(): void
    {
        $source = Environment::euListOfLists();

        $list = $this->loader()->load($source->toSource());

        self::assertSame('EU', $list->territory);
        self::assertGreaterThan(0, $list->sequenceNumber);
        self::assertGreaterThanOrEqual(27, \count($list->pointers), 'every member state should be pointed to');
        self::assertFalse($list->isExpiredAt(new \DateTimeImmutable()), 'the list of lists has passed its next update');
    }

    /**
     * A territory publishes both a machine-readable list and a document for
     * people to read. Following the wrong one fetches a PDF.
     */
    public function testTheEstonianPointerLeadsToTheMachineReadableList(): void
    {
        $list = $this->loader()->load(Environment::euListOfLists()->toSource());

        $pointer = $list->pointerTo('EE');

        self::assertNotNull($pointer);
        self::assertSame(TrustedListPointer::MIME_XML, $pointer->mimeType);
        self::assertStringEndsWith('.xml', $pointer->location);
        self::assertNotSame([], $pointer->signingCertificates, 'the list of lists must name who may sign the Estonian list');
    }

    public function testBothEstonianPointersArePublished(): void
    {
        $list = $this->loader()->load(Environment::euListOfLists()->toSource());

        $mimeTypes = array_map(
            static fn(TrustedListPointer $pointer): ?string => $pointer->mimeType,
            $list->pointersTo('EE'),
        );

        self::assertContains(TrustedListPointer::MIME_XML, $mimeTypes);
        self::assertContains(TrustedListPointer::MIME_PDF, $mimeTypes);
    }

    /**
     * The chain the whole arrangement exists for: shipped certificates verify
     * the list of lists, which names who may sign the Estonian list, which
     * names the authorities that issue Estonian certificates.
     */
    public function testTheEstonianTrustAnchorsCanBeReachedThroughTheChain(): void
    {
        $store = new ListOfListsTrustStore($this->loader(), Environment::euListOfLists());

        $store->load();

        $certificateAuthorities = $store->anchors([ServiceType::CaQc]);
        self::assertNotSame([], $certificateAuthorities, 'no qualified certificate authorities were found');

        $names = array_map(static fn($anchor): string => $anchor->certificate->subjectDn(), $store->anchors());
        $joined = implode(' | ', $names);

        // The authorities behind the eID means this library speaks to.
        self::assertStringContainsString('ESTEID2018', $joined, 'the IDEMIA card authority should be listed');
        self::assertMatchesRegularExpression('/EID-Q|EID-SK/', $joined, 'an authority issuing Mobile-ID and Smart-ID certificates should be listed');

        // And the services a signature needs beyond the signer's own chain.
        self::assertNotSame([], $store->anchors([ServiceType::TsaQtst, ServiceType::TsaTssQc, ServiceType::TsaTssAdes, ServiceType::Tsa]), 'no timestamping services were found');
        self::assertNotSame([], $store->anchors([ServiceType::OcspQc, ServiceType::Ocsp]), 'no validity confirmation services were found');
    }

    /**
     * A list of lists signed by something we do not ship must be refused, not
     * used. This is the check that makes shipping certificates worth anything.
     */
    public function testAListSignedByAnUnknownCertificateIsRefused(): void
    {
        $wrongSigners = [
            \Allkiri\Crypto\Certificate::fromPem(\Allkiri\Resources::read('trust/test/test-tsl-signer.pem')),
        ];
        $source = new ListOfListsSource(ListOfListsSource::EU_URL, $wrongSigners, ['EE']);

        $this->expectException(\Allkiri\Trust\TrustedList\TrustedListException::class);

        $this->loader()->load($source->toSource());
    }

    /**
     * The production environment is wired to the chain, so an application that
     * asks for it gets working trust without configuring anything.
     */
    public function testTheProductionEnvironmentTrustsWhatItShould(): void
    {
        $allkiri = new Allkiri(Environment::production(), self::http(60), new SystemClock(), new ArrayCache());

        $anchors = $allkiri->trustStore()->anchors([ServiceType::CaQc]);

        self::assertNotSame([], $anchors);
    }

    /**
     * The Estonian list is a version 6 list issued by the Information System
     * Authority, and it should not be stale.
     */
    public function testTheEstonianListIsCurrent(): void
    {
        $listOfLists = $this->loader()->load(Environment::euListOfLists()->toSource());
        $pointer = $listOfLists->pointerTo('EE');
        self::assertNotNull($pointer);

        $estonian = $this->loader()->load(Environment::euListOfLists()->sourceFor($pointer));

        self::assertSame('EE', $estonian->territory);
        self::assertStringContainsString('Information System Authority', $estonian->schemeOperatorName);
        self::assertFalse($estonian->isExpiredAt(new \DateTimeImmutable()), 'the Estonian trusted list has passed its next update');
    }

    /**
     * A signature made in another member state has to chain to that state's own
     * authorities, which the same list of lists carries. Following more than
     * one territory is how a relying party validates foreign signatures.
     */
    public function testOtherMemberStatesListsCanBeFollowedToo(): void
    {
        $store = new ListOfListsTrustStore($this->loader(), Environment::euListOfLists(['EE', 'LV', 'LT']));

        $store->load();

        $sources = [];
        foreach ($store->anchors() as $anchor) {
            $sources[$anchor->source] = true;
        }

        // Three lists were followed, and each contributed anchors of its own.
        self::assertGreaterThanOrEqual(3, \count($sources), 'each territory should contribute anchors: ' . implode(', ', array_keys($sources)));

        $names = implode(' | ', array_map(static fn($anchor): string => $anchor->certificate->subjectDn(), $store->anchors()));
        self::assertStringContainsString('ESTEID2018', $names, 'the Estonian card authority');
        self::assertMatchesRegularExpression('/C=LV|LATVIJ|Latvi/i', $names, 'a Latvian authority');
        self::assertMatchesRegularExpression('/C=LT|Lietuv|Registr/i', $names, 'a Lithuanian authority');
    }

    /**
     * The parser should not be the reason a list fails: check it reads the real
     * document rather than only our fixtures.
     */
    public function testTheParserReadsTheLiveListWithoutTheLoader(): void
    {
        $xml = self::http(60)->send(\Allkiri\Http\HttpRequest::get(ListOfListsSource::EU_URL))->body;

        $list = (new TrustedListParser())->parse($xml, 'EU list of trusted lists');

        self::assertSame('EU', $list->territory);
        self::assertSame([], $list->anchors, 'a list of lists publishes pointers, not services');
    }
}
