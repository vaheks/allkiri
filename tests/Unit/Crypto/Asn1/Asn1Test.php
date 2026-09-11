<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Crypto\Asn1;

use Allkiri\Crypto\Asn1\Asn1;
use Allkiri\Crypto\Asn1\Asn1Exception;
use Allkiri\Crypto\Asn1\DecodedElement;
use Allkiri\Crypto\Asn1\Maps\CmsMaps;
use Allkiri\Crypto\Asn1\Maps\OcspMaps;
use Allkiri\Crypto\Asn1\Maps\TspMaps;
use Allkiri\Crypto\Asn1\Node;
use Allkiri\Crypto\Asn1\Oids;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Tests\Support\Pki\TestPki;
use phpseclib3\File\ASN1 as PhpseclibAsn1;
use phpseclib3\Math\BigInteger;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Asn1::class)]
#[CoversClass(Node::class)]
#[CoversClass(DecodedElement::class)]
#[CoversClass(Oids::class)]
#[CoversClass(OcspMaps::class)]
#[CoversClass(CmsMaps::class)]
#[CoversClass(TspMaps::class)]
final class Asn1Test extends TestCase
{
    private const CAPTURED = __DIR__ . '/../../../fixtures/captured/';

    public function testNodeSlicesExactDerAndReadsPrimitives(): void
    {
        $cert = TestPki::signerEc256()->certificate;
        $root = Asn1::decodeRaw($cert->der());

        self::assertTrue($root->isSequence());
        self::assertSame($cert->der(), $root->der());
        self::assertSame(3, $root->childCount());
        self::assertSame($cert->tbsCertificateDer(), $root->child(0)->der());
        self::assertSame($cert->signatureValue(), $root->child(2)->bitStringBytes());
        self::assertSame('1.2.840.113549.1.1.11', $root->child(1)->child(0)->oid());

        $tbs = $root->child(0);
        $version = $tbs->tagged(0);
        self::assertNotNull($version);
        self::assertSame(0, $version->tag());
        self::assertSame('2', $version->child(0)->integer()->toString(), 'X.509 v3');
        self::assertSame('1001', $tbs->child(1)->integer()->toString());
        self::assertSame('2020-01-01T00:00:00+00:00', $tbs->child(4)->child(0)->time()->format(DATE_ATOM));
        self::assertSame(substr($tbs->der(), 4), $tbs->contentDer());
    }

    public function testDecodeRejectsGarbageAndTrailingBytes(): void
    {
        try {
            Asn1::decodeRaw('');
            self::fail('empty accepted');
        } catch (Asn1Exception) {
        }
        try {
            Asn1::decodeRaw(TestPki::ca()->certificate->der() . "\x00");
            self::fail('trailing byte accepted');
        } catch (Asn1Exception) {
        }

        $this->expectException(Asn1Exception::class);
        Asn1::decode("\x30\x03\x02\x01\x05", OcspMaps::OCSP_RESPONSE);
    }

    public function testOcspRequestEncodesAndDecodesBack(): void
    {
        $certId = [
            'hashAlgorithm' => ['algorithm' => Oids::SHA1],
            'issuerNameHash' => str_repeat("\x11", 20),
            'issuerKeyHash' => str_repeat("\x22", 20),
            'serialNumber' => new BigInteger('1001'),
        ];
        $nonce = str_repeat("\xab", 32);
        $der = Asn1::encode(['tbsRequest' => [
            'requestList' => [['reqCert' => $certId]],
            'requestExtensions' => [['extnId' => 'id-pkix-ocsp-nonce', 'critical' => false, 'extnValue' => Asn1::primitive(PhpseclibAsn1::TYPE_OCTET_STRING, $nonce)]],
        ]], OcspMaps::OCSP_REQUEST);

        $decoded = Asn1::decode($der, OcspMaps::OCSP_REQUEST);
        self::assertSame(str_repeat("\x11", 20), $decoded->string('tbsRequest', 'requestList', '0', 'reqCert', 'issuerNameHash'));
        $serial = $decoded->get('tbsRequest', 'requestList', '0', 'reqCert', 'serialNumber');
        self::assertInstanceOf(BigInteger::class, $serial);
        self::assertSame('1001', $serial->toString());
        self::assertSame(Oids::ID_PKIX_OCSP_NONCE, Oids::dotted($decoded->string('tbsRequest', 'requestExtensions', '0', 'extnId')));
        // The captured request our spike sent to demo.sk.ee has the same shape.
        $captured = Asn1::decode((string) file_get_contents(self::CAPTURED . 'demo-ocsp-request.der'), OcspMaps::OCSP_REQUEST);
        self::assertTrue($captured->has('tbsRequest', 'requestExtensions'));
    }

    public function testCapturedDemoOcspResponseDecodes(): void
    {
        $der = (string) file_get_contents(self::CAPTURED . 'demo-ocsp-response.ors');
        $response = Asn1::decode($der, OcspMaps::OCSP_RESPONSE);

        self::assertSame('successful', $response->string('responseStatus'));
        self::assertSame(Oids::ID_PKIX_OCSP_BASIC, Oids::dotted($response->string('responseBytes', 'responseType')));

        $basic = Asn1::decode($response->string('responseBytes', 'response'), OcspMaps::BASIC_OCSP_RESPONSE);
        self::assertTrue($basic->has('tbsResponseData', 'responderID', 'byName'));
        self::assertSame(['good'], array_keys($basic->array('tbsResponseData', 'responses', '0', 'certStatus')));
        self::assertSame(Oids::SHA1, Oids::dotted($basic->string('tbsResponseData', 'responses', '0', 'certID', 'hashAlgorithm', 'algorithm')));
        self::assertSame('2026-09-11T15:47:55+00:00', $basic->node()->child(0)->child(1)->time()->format(DATE_ATOM), 'producedAt from the raw tree');
        // certs [0] EXPLICIT SEQUENCE OF Certificate: slice the first one and parse it.
        $certs = $basic->node()->tagged(0);
        self::assertNotNull($certs);
        $responder = Certificate::fromDer($certs->child(0)->child(0)->der());
        self::assertSame('TEST of ESTEID2018 OCSP RESPONDER 202609', $responder->commonName());
        self::assertTrue($responder->hasExtendedKeyUsage(Oids::ID_KP_OCSP_SIGNING));
    }

    public function testCapturedDemoTimestampDecodesDownToTstInfo(): void
    {
        $der = (string) file_get_contents(self::CAPTURED . 'demo-tsa-response.tsr');
        $response = Asn1::decode($der, TspMaps::TIME_STAMP_RESP);
        $status = $response->get('status', 'status');
        self::assertInstanceOf(BigInteger::class, $status);
        self::assertSame('0', $status->toString(), 'granted');
        self::assertSame(Oids::ID_SIGNED_DATA, Oids::dotted($response->string('timeStampToken', 'contentType')));

        $token = $response->node()->child(1);
        $signedData = $token->child(1)->child(0)->map(CmsMaps::SIGNED_DATA);
        self::assertSame(Oids::ID_CT_TST_INFO, Oids::dotted($signedData->string('encapContentInfo', 'eContentType')));
        self::assertCount(1, $signedData->array('signerInfos'));
        self::assertSame(Oids::SHA512, Oids::dotted($signedData->string('signerInfos', '0', 'digestAlgorithm', 'algorithm')));

        $tstInfo = Asn1::decode($signedData->string('encapContentInfo', 'eContent'), TspMaps::TST_INFO);
        self::assertSame(Oids::SK_TSA_POLICY_QTST, Oids::dotted($tstInfo->string('policy')));
        self::assertSame(HashAlgorithm::SHA256->digest((string) file_get_contents(self::CAPTURED . 'demo-tsa-timestamped-data.bin')), $tstInfo->string('messageImprint', 'hashedMessage'));
        self::assertSame('2026-09-11T15:36:38+00:00', $tstInfo->node()->child(4)->time()->format(DATE_ATOM));
        self::assertTrue($tstInfo->has('nonce'));
        self::assertTrue($tstInfo->has('tsa', 'directoryName'));

        // The ESS signing-certificate attribute's hash matches the embedded TSU certificate.
        $tsuCert = Certificate::fromDer($signedData->node()->tagged(0)?->child(0)->der() ?? '');
        self::assertSame('DEMO SK TIMESTAMPING UNIT 2025E', $tsuCert->commonName());
        $signerInfo = $signedData->node()->child($signedData->node()->childCount() - 1)->child(0);
        $signedAttrs = $signerInfo->tagged(0);
        self::assertNotNull($signedAttrs);
        $found = false;
        foreach ($signedAttrs->children() as $attribute) {
            if ($attribute->child(0)->oid() === Oids::ID_AA_SIGNING_CERTIFICATE_V2) {
                $ess = $attribute->child(1)->child(0)->map(CmsMaps::SIGNING_CERTIFICATE_V2);
                self::assertSame(HashAlgorithm::SHA256->digest($tsuCert->der()), $ess->string('certs', '0', 'certHash'));
                $found = true;
            }
        }
        self::assertTrue($found, 'signingCertificateV2 attribute present');
    }

    public function testOidsResolveNamesAndPassDottedThrough(): void
    {
        self::assertSame('1.2.840.113549.1.1.11', Oids::dotted('sha256WithRSAEncryption'));
        self::assertSame(Oids::ID_PKIX_OCSP_NONCE, Oids::dotted('id-pkix-ocsp-nonce'));
        self::assertSame('1.2.3.4', Oids::dotted('1.2.3.4'));
        self::assertSame('no-such-name', Oids::dotted('no-such-name'));
    }
}
