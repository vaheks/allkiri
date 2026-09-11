<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Pki;

use Allkiri\Crypto\Asn1\Asn1;
use Allkiri\Crypto\Asn1\Oids;
use Allkiri\Crypto\EcdsaSignature;
use Allkiri\Crypto\KeyPair;
use Allkiri\Crypto\KeyType;
use Allkiri\Crypto\Ocsp\CertStatus;
use Allkiri\Crypto\Ocsp\OcspRequest;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Http\HttpRequest;
use Allkiri\Http\HttpResponse;
use Allkiri\Tests\Support\Http\MockHttpClient;
use phpseclib3\File\ASN1 as PhpseclibAsn1;
use Psr\Clock\ClockInterface;

/**
 * An in-process RFC 6960 responder for offline tests: answers "good" for
 * every serial unless told otherwise, echoes the nonce, signs with the test
 * responder key and ships its certificate — the delegated-responder model SK uses.
 */
final class MockOcspResponder
{
    public const URL = 'http://ocsp.allkiri.test/';

    /** @var array<string, array{CertStatus, ?\DateTimeImmutable}> serial => status */
    private array $statuses = [];

    public bool $omitNonce = false;
    public bool $wrongNonce = false;
    public bool $wrongCertId = false;
    public bool $corruptSignature = false;
    public bool $includeCertificate = true;
    public bool $unauthorizedStatus = false;
    public int $producedAtOffsetSeconds = 0;
    public ?int $nextUpdateInSeconds = null;
    public int $requests = 0;

    public function __construct(
        private readonly ClockInterface $clock,
        private readonly KeyPair $responder,
    ) {}

    public static function register(MockHttpClient $http, ClockInterface $clock, ?KeyPair $responder = null): self
    {
        $mock = new self($clock, $responder ?? TestPki::ocspResponder());
        $http->on(self::URL, $mock->handle(...));

        return $mock;
    }

    public function revoke(string $serialNumber, \DateTimeImmutable $at): void
    {
        $this->statuses[$serialNumber] = [CertStatus::Revoked, $at];
    }

    public function unknown(string $serialNumber): void
    {
        $this->statuses[$serialNumber] = [CertStatus::Unknown, null];
    }

    public function handle(HttpRequest $request): HttpResponse
    {
        ++$this->requests;
        if ($this->unauthorizedStatus) {
            return new HttpResponse(200, ['Content-Type' => 'application/ocsp-response'], Asn1::sequence(["\x0a\x01\x06"]));
        }
        $req = OcspRequest::fromDer($request->body);
        $producedAt = $this->clock->now()->modify(\sprintf('%+d seconds', $this->producedAtOffsetSeconds));
        [$status, $revokedAt] = $this->statuses[$req->certId->serialNumber] ?? [CertStatus::Good, null];

        $certId = $req->certId->toMapped();
        if ($this->wrongCertId) {
            $certId['serialNumber'] = (new \phpseclib3\Math\BigInteger($req->certId->serialNumber))->add(new \phpseclib3\Math\BigInteger(1));
        }
        $certIdDer = Asn1::encode($certId, \Allkiri\Crypto\Asn1\Maps\OcspMaps::CERT_ID);
        $statusDer = match ($status) {
            CertStatus::Good => "\x80\x00",
            CertStatus::Unknown => "\x82\x00",
            CertStatus::Revoked => Asn1::implicit(1, Asn1::sequence([Asn1Encoders::generalizedTime($revokedAt ?? $producedAt)])),
        };
        $singleParts = [$certIdDer, $statusDer, Asn1Encoders::generalizedTime($producedAt)];
        if ($this->nextUpdateInSeconds !== null) {
            $singleParts[] = Asn1::explicit(0, Asn1Encoders::generalizedTime($producedAt->modify(\sprintf('%+d seconds', $this->nextUpdateInSeconds))));
        }
        $tbsParts = [
            Asn1::explicit(1, $this->responder->certificate->subjectNameDer()),
            Asn1Encoders::generalizedTime($producedAt),
            Asn1::sequence([Asn1::sequence($singleParts)]),
        ];
        if ($req->nonce !== null && !$this->omitNonce) {
            $nonce = $this->wrongNonce ? strrev($req->nonce) : $req->nonce;
            $extension = Asn1::sequence([
                Asn1::primitive(PhpseclibAsn1::TYPE_OBJECT_IDENTIFIER, Oids::ID_PKIX_OCSP_NONCE),
                Asn1::primitive(PhpseclibAsn1::TYPE_OCTET_STRING, Asn1::primitive(PhpseclibAsn1::TYPE_OCTET_STRING, $nonce)),
            ]);
            $tbsParts[] = Asn1::explicit(1, Asn1::sequence([$extension]));
        }
        $tbs = Asn1::sequence($tbsParts);

        $algorithm = $this->responder->privateKey->keyType() === KeyType::EC ? SignatureAlgorithm::ES256 : SignatureAlgorithm::RS256;
        $signature = $this->responder->privateKey->sign($algorithm, $tbs);
        if ($algorithm->keyType() === KeyType::EC) {
            $signature = EcdsaSignature::rawToDer($signature);
        }
        if ($this->corruptSignature) {
            $signature[5] = \chr(\ord($signature[5]) ^ 0x01);
        }
        $basicParts = [
            $tbs,
            Asn1Encoders::algorithmIdentifier($algorithm->oid() ?? '', $algorithm->keyType() === KeyType::RSA),
            Asn1::primitive(PhpseclibAsn1::TYPE_BIT_STRING, "\x00" . $signature),
        ];
        if ($this->includeCertificate) {
            $basicParts[] = Asn1::explicit(0, Asn1::sequence([$this->responder->certificate->der()]));
        }
        $basic = Asn1::sequence($basicParts);
        $response = Asn1::sequence([
            "\x0a\x01\x00",
            Asn1::explicit(0, Asn1::sequence([
                Asn1::primitive(PhpseclibAsn1::TYPE_OBJECT_IDENTIFIER, Oids::ID_PKIX_OCSP_BASIC),
                Asn1::primitive(PhpseclibAsn1::TYPE_OCTET_STRING, $basic),
            ])),
        ]);

        return new HttpResponse(200, ['Content-Type' => 'application/ocsp-response'], $response);
    }
}
