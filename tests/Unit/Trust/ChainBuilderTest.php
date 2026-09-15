<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Trust;

use Allkiri\Crypto\AlgorithmConstraints;
use Allkiri\Crypto\Certificate;
use Allkiri\Tests\Support\Crypto\DerPatch;
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
use phpseclib3\Math\BigInteger;
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

    /**
     * #27: a CA that signs with RSASSA-PSS, in the profile allkiri accepts and
     * with a salt it does not.
     */
    public function testACertificateIssuedWithRsassaPssChains(): void
    {
        $store = InMemoryTrustStore::fromCertificates([TestPki::ca()->certificate], ServiceType::CaQc);
        $at = new \DateTimeImmutable('2026-01-01T00:00:00Z');
        $pss = TestCertificates::issue(TestKey::ec(label: 'chained with PSS'), ['id-at-commonName' => 'allkiri PSS leaf'], signature: TestCertificateSignature::Pss256)->certificate;
        self::assertSame(2, (new ChainBuilder($store))->build($pss, [], $at, ServiceType::caTypes())->length());

        $salt20 = TestCertificates::issue(TestKey::ec(label: 'chained with PSS'), ['id-at-commonName' => 'allkiri PSS leaf'], signature: TestCertificateSignature::Pss256Salt20)->certificate;
        try {
            (new ChainBuilder($store))->build($salt20, [], $at, ServiceType::caTypes());
            self::fail('a 20-byte PSS salt was accepted');
        } catch (ChainBuildingException $e) {
            self::assertSame(ChainBuildingException::REASON_UNSUPPORTED_ALGORITHM, $e->reason);
            self::assertStringContainsString('20-byte salt', $e->getMessage());
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

    public function testAPathLengthConstraintIsHeldTo(): void
    {
        $at = new \DateTimeImmutable('2026-01-01T00:00:00Z');
        $rootStore = InMemoryTrustStore::fromCertificates([TestPki::ca()->certificate], ServiceType::CaQc);
        // A CA that may have no CA below it, and one below it anyway.
        $limited = self::ca('allkiri Limited CA', pathLen: 0);
        $below = self::ca('allkiri CA Below The Limit', $limited);
        $leaf = self::leaf($below);

        try {
            (new ChainBuilder($rootStore))->build($leaf, [$below->certificate, $limited->certificate], $at, ServiceType::caTypes());
            self::fail('a CA below a pathLen 0 CA was accepted');
        } catch (ChainBuildingException $e) {
            self::assertSame(ChainBuildingException::REASON_PATH_LENGTH, $e->reason);
        }

        // The limit holds when the limited CA is the trust anchor, too.
        try {
            (new ChainBuilder(InMemoryTrustStore::fromCertificates([$limited->certificate], ServiceType::CaQc)))->build($leaf, [$below->certificate], $at, ServiceType::caTypes());
            self::fail('a trust anchor\'s pathLen 0 was ignored');
        } catch (ChainBuildingException $e) {
            self::assertSame(ChainBuildingException::REASON_PATH_LENGTH, $e->reason);
        }

        // A leaf directly below it is what pathLen 0 allows.
        self::assertSame(3, (new ChainBuilder($rootStore))->build(self::leaf($limited), [$limited->certificate], $at, ServiceType::caTypes())->length());
        // And pathLen 1 allows one CA below.
        $roomier = self::ca('allkiri CA Allowing One', pathLen: 1);
        $underRoomier = self::ca('allkiri CA Under One', $roomier);
        self::assertSame(4, (new ChainBuilder($rootStore))->build(self::leaf($underRoomier), [$underRoomier->certificate, $roomier->certificate], $at, ServiceType::caTypes())->length());
    }

    /**
     * A CA that certifies its own new key under the same name adds a
     * certificate to the path but not a level, and RFC 5280 does not count it.
     */
    public function testASelfIssuedCertificateDoesNotCountTowardsThePathLength(): void
    {
        $limited = self::ca('allkiri Rollover CA', pathLen: 0);
        $newKey = TestKey::ec(label: 'allkiri Rollover CA, new key');
        $rolledOver = TestIssuer::of(TestCertificates::issue($newKey, ['id-at-commonName' => 'allkiri Rollover CA'], [
            'id-ce-basicConstraints' => [['cA' => true, 'pathLenConstraint' => new BigInteger(0)], true],
            'id-ce-keyUsage' => [['keyCertSign', 'cRLSign'], true],
            'id-pe-authorityInfoAccess' => null,
        ], $limited), $newKey);
        $store = InMemoryTrustStore::fromCertificates([TestPki::ca()->certificate], ServiceType::CaQc);

        $chain = (new ChainBuilder($store))->build(self::leaf($rolledOver), [$rolledOver->certificate, $limited->certificate], new \DateTimeImmutable('2026-01-01T00:00:00Z'), ServiceType::caTypes());

        self::assertSame(4, $chain->length());
    }

    public function testAnIntermediateNotAllowedToSignCertificatesIsRefused(): void
    {
        $at = new \DateTimeImmutable('2026-01-01T00:00:00Z');
        $store = InMemoryTrustStore::fromCertificates([TestPki::ca()->certificate], ServiceType::CaQc);
        $notForCertificates = self::ca('allkiri CA Without keyCertSign', keyUsage: ['digitalSignature']);

        try {
            (new ChainBuilder($store))->build(self::leaf($notForCertificates), [$notForCertificates->certificate], $at, ServiceType::caTypes());
            self::fail('an intermediate without keyCertSign issued a certificate');
        } catch (ChainBuildingException $e) {
            self::assertSame(ChainBuildingException::REASON_CA_KEY_USAGE, $e->reason);
        }

        // One that does not restrict its key usage at all is not refused for it.
        $unrestricted = self::ca('allkiri CA Without Key Usage', keyUsage: null);
        self::assertSame(3, (new ChainBuilder($store))->build(self::leaf($unrestricted), [$unrestricted->certificate], $at, ServiceType::caTypes())->length());
    }

    public function testAnIssuerKeyThatCannotBeReadIsAReasonNotAnException(): void
    {
        $unreadable = DerPatch::unreadableKey(TestPki::ca()->certificate);

        try {
            (new ChainBuilder(new InMemoryTrustStore([])))->build(TestPki::signerEc256()->certificate, [$unreadable], new \DateTimeImmutable('2026-01-01T00:00:00Z'), ServiceType::caTypes());
            self::fail('an issuer whose key cannot be read was accepted');
        } catch (ChainBuildingException $e) {
            self::assertSame(ChainBuildingException::REASON_UNSUPPORTED_ALGORITHM, $e->reason);
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

    /**
     * A CA issued in the test, by the committed test CA unless another issuer is given.
     *
     * @param list<string>|null $keyUsage null leaves the key usage extension out
     */
    private static function ca(string $name, ?TestIssuer $issuer = null, ?int $pathLen = null, ?array $keyUsage = ['keyCertSign', 'cRLSign']): TestIssuer
    {
        $key = TestKey::ec(label: $name);
        $basicConstraints = $pathLen === null ? ['cA' => true] : ['cA' => true, 'pathLenConstraint' => new BigInteger($pathLen)];
        $issued = TestCertificates::issue($key, ['id-at-commonName' => $name], [
            'id-ce-basicConstraints' => [$basicConstraints, true],
            'id-ce-keyUsage' => $keyUsage === null ? null : [$keyUsage, true],
            'id-pe-authorityInfoAccess' => null,
        ], $issuer);

        return TestIssuer::of($issued, $key);
    }

    private static function leaf(TestIssuer $issuer): Certificate
    {
        return TestCertificates::issue(TestKey::ec(label: 'leaf of ' . $issuer->certificate->subjectDn()), ['id-at-commonName' => 'allkiri Test Leaf'], issuer: $issuer)->certificate;
    }
}
