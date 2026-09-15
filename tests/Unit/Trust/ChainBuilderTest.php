<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Trust;

use Allkiri\Crypto\AlgorithmConstraints;
use Allkiri\Crypto\Certificate;
use Allkiri\Tests\Support\Pki\Asn1Encoders;
use Allkiri\Tests\Support\Pki\TestCertificates;
use Allkiri\Tests\Support\Pki\TestCertificateSignature;
use Allkiri\Tests\Support\Pki\TestIssuer;
use Allkiri\Tests\Support\Pki\TestKey;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Trust\ChainBuilder;
use Allkiri\Trust\ChainBuildingException;
use Allkiri\Trust\CompositeTrustStore;
use Allkiri\Trust\InMemoryTrustStore;
use Allkiri\Trust\ServiceStatus;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustAnchor;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class ChainBuilderTest extends TestCase
{
    private const CERTS = __DIR__ . '/../../fixtures/certs/';

    public function testLeafDirectlyUnderAnAnchor(): void
    {
        $store = InMemoryTrustStore::fromCertificates([TestPki::ca()->certificate], ServiceType::CaQc, 'test');
        $chain = (new ChainBuilder($store))->build(TestPki::signerEc256()->certificate, [], new \DateTimeImmutable('2026-03-01T00:00:00Z'), ServiceType::caTypes());

        self::assertSame(2, $chain->length());
        self::assertTrue($chain->leaf()->equals(TestPki::signerEc256()->certificate));
        self::assertTrue($chain->issuerOfLeaf()->equals(TestPki::ca()->certificate));
        self::assertSame(ServiceType::CaQc, $chain->anchor->serviceType);
        self::assertSame('allkiri Test CA', $chain->anchor->serviceName);
        self::assertCount(1, $chain->caCertificates());
        self::assertTrue($chain->contains(TestPki::ca()->certificate));
    }

    public function testRealThreeLevelSkTestChainThroughAnIntermediate(): void
    {
        $leaf = Certificate::fromPem((string) file_get_contents(self::CERTS . 'TEST_ESTEID2018_signer_JOEORG.pem'));
        $intermediate = Certificate::fromPem((string) file_get_contents(self::CERTS . 'TEST_of_ESTEID2018.pem'));
        $root = Certificate::fromPem((string) file_get_contents(self::CERTS . 'TEST_of_EE_GovCA2018.pem'));
        $unrelated = Certificate::fromPem((string) file_get_contents(self::CERTS . 'testESTEID2025.pem'));
        $at = new \DateTimeImmutable('2024-09-02T12:36:44Z');

        $rootStore = InMemoryTrustStore::fromCertificates([$root], ServiceType::CaQc, 'tl');
        $chain = (new ChainBuilder($rootStore))->build($leaf, [$unrelated, $intermediate], $at, ServiceType::caTypes());
        self::assertSame(3, $chain->length());
        self::assertTrue($chain->certificates[1]->equals($intermediate));
        self::assertTrue($chain->certificates[2]->equals($root));

        // The test trusted list anchors the issuing CA itself, giving a two-step chain.
        $caStore = InMemoryTrustStore::fromCertificates([$intermediate], ServiceType::CaQc, 'tl');
        self::assertSame(2, (new ChainBuilder($caStore))->build($leaf, [], $at, ServiceType::caTypes())->length());

        // Without the intermediate nothing links the leaf to the root.
        try {
            (new ChainBuilder($rootStore))->build($leaf, [], $at, ServiceType::caTypes());
            self::fail('chain built without the intermediate');
        } catch (ChainBuildingException $e) {
            self::assertSame(ChainBuildingException::REASON_NO_ISSUER, $e->reason);
        }
    }

    public function testAnchorMayBeTheCertificateItself(): void
    {
        $tsa = TestPki::tsa()->certificate;
        $store = new CompositeTrustStore(
            InMemoryTrustStore::fromCertificates([TestPki::ca()->certificate], ServiceType::CaQc),
            InMemoryTrustStore::fromCertificates([$tsa], ServiceType::TsaQtst, 'tl'),
        );
        $chain = (new ChainBuilder($store))->build($tsa, [], new \DateTimeImmutable('2026-01-01T00:00:00Z'), ServiceType::tsaTypes());

        self::assertSame(1, $chain->length());
        self::assertSame(ServiceType::TsaQtst, $chain->anchor->serviceType);
        self::assertTrue($chain->issuerOfLeaf()->equals($tsa));

        // With only CA anchors accepted, the TSA certificate chains to the CA instead.
        $viaCa = (new ChainBuilder($store))->build($tsa, [], new \DateTimeImmutable('2026-01-01T00:00:00Z'), ServiceType::caTypes());
        self::assertSame(2, $viaCa->length());
    }

    public function testValidityAndStatusAreCheckedAtTheGivenTime(): void
    {
        $ca = TestPki::ca()->certificate;
        $leaf = TestPki::signerRsa()->certificate;
        $builder = new ChainBuilder(InMemoryTrustStore::fromCertificates([$ca], ServiceType::CaQc));

        try {
            $builder->build($leaf, [], new \DateTimeImmutable('2019-06-01T00:00:00Z'), ServiceType::caTypes());
            self::fail('leaf accepted before notBefore');
        } catch (ChainBuildingException $e) {
            self::assertSame(ChainBuildingException::REASON_NOT_VALID_AT_TIME, $e->reason);
        }

        $withdrawn = new TrustAnchor($ca, ServiceType::CaQc, 'withdrawn CA', [
            ['status' => ServiceStatus::Granted, 'since' => new \DateTimeImmutable('2020-01-01T00:00:00Z')],
            ['status' => ServiceStatus::Withdrawn, 'since' => new \DateTimeImmutable('2025-01-01T00:00:00Z')],
        ], 'tl');
        $withdrawnBuilder = new ChainBuilder(new InMemoryTrustStore([$withdrawn]));
        self::assertSame(2, $withdrawnBuilder->build($leaf, [], new \DateTimeImmutable('2024-06-01T00:00:00Z'), ServiceType::caTypes())->length());
        try {
            $withdrawnBuilder->build($leaf, [], new \DateTimeImmutable('2025-06-01T00:00:00Z'), ServiceType::caTypes());
            self::fail('withdrawn anchor accepted');
        } catch (ChainBuildingException $e) {
            self::assertSame(ChainBuildingException::REASON_ANCHOR_STATUS, $e->reason);
        }

        try {
            (new ChainBuilder(InMemoryTrustStore::fromCertificates([$ca], ServiceType::TsaQtst)))->build($leaf, [], new \DateTimeImmutable('2026-01-01T00:00:00Z'), ServiceType::caTypes());
            self::fail('TSA anchor accepted as a CA');
        } catch (ChainBuildingException $e) {
            self::assertSame(ChainBuildingException::REASON_ANCHOR_TYPE, $e->reason);
        }
    }

    public function testForgedIssuerIsRejected(): void
    {
        $zetesRoot = Certificate::fromPem((string) file_get_contents(self::CERTS . 'testEEGovCA2025.pem'));
        $leaf = TestPki::signerEc256()->certificate;
        // An anchor with the right name but the wrong key cannot exist in practice; simulate by using a store whose only anchor does not verify.
        $store = InMemoryTrustStore::fromCertificates([$zetesRoot], ServiceType::CaQc);

        $this->expectException(ChainBuildingException::class);
        (new ChainBuilder($store))->build($leaf, [], new \DateTimeImmutable('2026-01-01T00:00:00Z'), ServiceType::caTypes());
    }

    public function testACertificateSignedWithSha1IsNotAccepted(): void
    {
        $leaf = TestCertificates::issue(TestKey::ec(label: 'sha1-leaf'), ['id-at-commonName' => 'allkiri SHA-1 leaf'], signature: TestCertificateSignature::Sha1)->certificate;
        $store = InMemoryTrustStore::fromCertificates([TestPki::ca()->certificate], ServiceType::CaQc);

        try {
            (new ChainBuilder($store))->build($leaf, [], new \DateTimeImmutable('2026-01-01T00:00:00Z'), ServiceType::caTypes());
            self::fail('a certificate signed with SHA-1 was accepted');
        } catch (ChainBuildingException $e) {
            self::assertSame(ChainBuildingException::REASON_ALGORITHM_NOT_ACCEPTED, $e->reason);
            self::assertStringEndsWith('is signed with SHA-1, which is no longer accepted', $e->getMessage());
        }
    }

    public function testTheRsaKeyFloorAppliesToTheIssuersKey(): void
    {
        $store = InMemoryTrustStore::fromCertificates([TestPki::ca()->certificate], ServiceType::CaQc);
        $leaf = TestPki::signerEc256()->certificate;
        $at = new \DateTimeImmutable('2026-01-01T00:00:00Z');
        self::assertSame(2, (new ChainBuilder($store))->build($leaf, [], $at, ServiceType::caTypes())->length());

        try {
            (new ChainBuilder($store, new AlgorithmConstraints(4096)))->build($leaf, [], $at, ServiceType::caTypes());
            self::fail('the 3072-bit CA key met a 4096-bit floor');
        } catch (ChainBuildingException $e) {
            self::assertSame(ChainBuildingException::REASON_ALGORITHM_NOT_ACCEPTED, $e->reason);
            self::assertStringContainsString('3072-bit', $e->getMessage());
        }
    }

    /**
     * An algorithm allkiri cannot verify says nothing about whether the
     * certificate is genuine, so it is not reported as a bad signature.
     */
    public function testAnUnsupportedAlgorithmIsNotReportedAsABadSignature(): void
    {
        // sha224WithRSAEncryption, named in both places a certificate names its algorithm.
        $der = str_replace(
            Asn1Encoders::algorithmIdentifier('1.2.840.113549.1.1.11', true),
            Asn1Encoders::algorithmIdentifier('1.2.840.113549.1.1.14', true),
            TestPki::signerEc256()->certificate->der(),
            $count,
        );
        self::assertSame(2, $count);
        $store = InMemoryTrustStore::fromCertificates([TestPki::ca()->certificate], ServiceType::CaQc);

        try {
            (new ChainBuilder($store))->build(Certificate::fromDer($der), [], new \DateTimeImmutable('2026-01-01T00:00:00Z'), ServiceType::caTypes());
            self::fail('a certificate with an unknown algorithm was accepted');
        } catch (ChainBuildingException $e) {
            self::assertSame(ChainBuildingException::REASON_UNSUPPORTED_ALGORITHM, $e->reason);
        }
    }

    /**
     * When no path works, the report names the failure that got furthest. A
     * real intermediate signed with SHA-1 sits beside a same-named certificate
     * that never signed the leaf; whichever is tried last, the SHA-1 link is
     * what is reported, not the certificate that was never the issuer.
     */
    public function testTheFailureThatGotFurthestIsReported(): void
    {
        $name = ['id-at-commonName' => 'allkiri Test Intermediate'];
        $asCa = ['id-ce-basicConstraints' => [['cA' => true], true], 'id-ce-keyUsage' => [['keyCertSign', 'cRLSign'], true]];
        $key = TestKey::ec(label: 'ranked-intermediate');
        $intermediate = TestCertificates::issue($key, $name, $asCa, signature: TestCertificateSignature::Sha1)->certificate;
        $impostor = TestCertificates::issue(TestKey::ec(label: 'ranked-impostor'), $name, $asCa)->certificate;
        $leaf = TestCertificates::issue(TestKey::ec(label: 'ranked-leaf'), ['id-at-commonName' => 'allkiri Test Leaf'], issuer: new TestIssuer($intermediate, $key))->certificate;
        $builder = new ChainBuilder(InMemoryTrustStore::fromCertificates([TestPki::ca()->certificate], ServiceType::CaQc));

        foreach ([[$intermediate, $impostor], [$impostor, $intermediate]] as $intermediates) {
            try {
                $builder->build($leaf, $intermediates, new \DateTimeImmutable('2026-01-01T00:00:00Z'), ServiceType::caTypes());
                self::fail('a chain through a SHA-1 link was built');
            } catch (ChainBuildingException $e) {
                self::assertSame(ChainBuildingException::REASON_ALGORITHM_NOT_ACCEPTED, $e->reason);
            }
        }
    }

    public function testStatusHistoryAndServiceTypeHelpers(): void
    {
        $anchor = TrustAnchor::manual(TestPki::ca()->certificate, ServiceType::CaQc);
        self::assertSame(ServiceStatus::Granted, $anchor->currentStatus());
        self::assertTrue($anchor->isTrustworthyAt(new \DateTimeImmutable('1990-01-01T00:00:00Z')));
        self::assertTrue(ServiceStatus::UnderSupervision->isTrustworthy());
        self::assertFalse(ServiceStatus::SupervisionRevoked->isTrustworthy());
        self::assertTrue(ServiceType::TsaTssQc->isTsa());
        self::assertTrue(ServiceType::OcspQc->isOcsp());
        self::assertFalse(ServiceType::CaPkc->isTsa());
        self::assertNull(ServiceType::tryFrom('http://uri.etsi.org/TrstSvc/Svctype/unknown'));
    }
}
