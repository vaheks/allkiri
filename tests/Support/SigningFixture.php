<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\KeyPair;
use Allkiri\Crypto\Ocsp\OcspClient;
use Allkiri\Crypto\Ocsp\OcspVerificationOptions;
use Allkiri\Crypto\Tsp\TspClient;
use Allkiri\Signing\SigningService;
use Allkiri\Tests\Support\Clock\FrozenClock;
use Allkiri\Tests\Support\Crypto\FixedNonceGenerator;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Tests\Support\Pki\MockOcspResponder;
use Allkiri\Tests\Support\Pki\MockTsa;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Trust\ChainBuilder;
use Allkiri\Trust\CompositeTrustStore;
use Allkiri\Trust\InMemoryTrustStore;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustStore;
use Allkiri\Xades\LtaExtender;
use Allkiri\Xades\LtExtender;
use Allkiri\Xades\SignatureBuilder;

/**
 * A complete offline signing environment: the test PKI, a mock timestamp
 * authority and a mock OCSP responder, wired the way production would be.
 *
 * Everything runs in-process, so the whole LT pipeline is exercised in unit
 * tests with no network and no eID hardware.
 */
final class SigningFixture
{
    public readonly MockHttpClient $http;

    public readonly MockTsa $tsa;

    public readonly MockOcspResponder $ocsp;

    public readonly TrustStore $trustStore;

    public readonly ChainBuilder $chainBuilder;

    public readonly SigningService $signingService;

    /**
     * @param list<Certificate> $extraCas      trusted as qualified CAs beside the test CA, for signing with certificates issued in a test
     * @param KeyPair|null      $tsa           the timestamp authority, trusted as one; the committed test TSA when null
     * @param KeyPair|null      $ocspResponder the OCSP responder, trusted as one; the committed test responder when null
     */
    public function __construct(
        public readonly FrozenClock $clock = new FrozenClock('2026-03-01T10:00:00Z'),
        array $extraCas = [],
        ?KeyPair $tsa = null,
        ?KeyPair $ocspResponder = null,
    ) {
        $tsa ??= TestPki::tsa();
        $ocspResponder ??= TestPki::ocspResponder();
        $this->http = new MockHttpClient();
        $this->tsa = MockTsa::register($this->http, $this->clock, $tsa);
        $this->ocsp = MockOcspResponder::register($this->http, $this->clock, $ocspResponder);

        $this->trustStore = new CompositeTrustStore(
            InMemoryTrustStore::fromCertificates([TestPki::ca()->certificate, ...$extraCas], ServiceType::CaQc, 'test PKI'),
            InMemoryTrustStore::fromCertificates([$tsa->certificate], ServiceType::TsaQtst, 'test PKI'),
            InMemoryTrustStore::fromCertificates([$ocspResponder->certificate], ServiceType::OcspQc, 'test PKI'),
        );
        $this->chainBuilder = new ChainBuilder($this->trustStore);

        $tspClient = new TspClient($this->http, MockTsa::URL, nonces: new FixedNonceGenerator('tsa'));
        $ocspClient = new OcspClient(
            $this->http,
            $this->clock,
            nonces: new FixedNonceGenerator('ocsp'),
            options: OcspVerificationOptions::forSigning(),
        );

        $this->signingService = new SigningService(
            $this->clock,
            new LtExtender($tspClient, $ocspClient, $this->chainBuilder, $this->trustStore),
            new LtaExtender($tspClient),
            new SignatureBuilder($this->clock),
        );
    }

    /**
     * A signing service with no timestamp or OCSP service configured.
     */
    public function besOnlyService(): SigningService
    {
        return new SigningService($this->clock, null, null, new SignatureBuilder($this->clock));
    }
}
