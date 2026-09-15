<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\Pki;

use Allkiri\Crypto\Asn1\Asn1;
use Allkiri\Crypto\Asn1\Oids;
use Allkiri\Crypto\KeyPair;
use Allkiri\Crypto\Tsp\TimestampRequest;
use Allkiri\Http\HttpRequest;
use Allkiri\Http\HttpResponse;
use Allkiri\Tests\Support\Http\MockHttpClient;
use phpseclib3\File\ASN1 as PhpseclibAsn1;
use Psr\Clock\ClockInterface;

/**
 * An in-process RFC 3161 TSA for offline tests. Register it on a
 * MockHttpClient; every knob produces a specific defect for negative tests.
 */
final class MockTsa
{
    public const URL = 'http://tsa.allkiri.test/tsa';

    public const POLICY = '1.3.6.1.4.1.99999.1.1';

    public bool $includeCertificate = true;
    public bool $corruptSignature = false;
    public bool $wrongImprint = false;
    public bool $omitNonce = false;
    public bool $reject = false;
    public int $genTimeOffsetSeconds = 0;
    public int $requests = 0;

    /**
     * Signs in place of the TSA key's usual algorithm, as {@see TestSignatures} does.
     *
     * @var (\Closure(string): array{string, string})|null
     */
    public ?\Closure $sign = null;
    private int $serial = 1000;

    public function __construct(
        private readonly ClockInterface $clock,
        private readonly KeyPair $tsa,
    ) {}

    public static function register(MockHttpClient $http, ClockInterface $clock, ?KeyPair $tsa = null): self
    {
        $mock = new self($clock, $tsa ?? TestPki::tsa());
        $http->on(self::URL, $mock->handle(...));

        return $mock;
    }

    public function handle(HttpRequest $request): HttpResponse
    {
        ++$this->requests;
        $req = TimestampRequest::fromDer($request->body);
        if ($this->reject) {
            $der = Asn1::sequence([Asn1::sequence([Asn1::integer(2), Asn1::sequence([Asn1::primitive(PhpseclibAsn1::TYPE_UTF8_STRING, 'rejected by test TSA')])])]);

            return new HttpResponse(200, ['Content-Type' => 'application/timestamp-reply'], $der);
        }
        $genTime = $this->clock->now()->modify(\sprintf('%+d seconds', $this->genTimeOffsetSeconds));
        $imprint = $this->wrongImprint ? strrev($req->imprint) : $req->imprint;

        $tstParts = [
            Asn1::integer(1),
            Asn1::primitive(PhpseclibAsn1::TYPE_OBJECT_IDENTIFIER, self::POLICY),
            Asn1::sequence([Asn1Encoders::algorithmIdentifier($req->hashAlgorithm->oid()), Asn1::primitive(PhpseclibAsn1::TYPE_OCTET_STRING, $imprint)]),
            Asn1::integer(++$this->serial),
            Asn1Encoders::generalizedTime($genTime),
            Asn1::sequence([Asn1::integer(1)]), // accuracy: 1 second
        ];
        if ($req->nonce !== null && !$this->omitNonce) {
            $tstParts[] = Asn1::integer($req->nonce);
        }
        $tstInfo = Asn1::sequence($tstParts);
        $token = Asn1Encoders::signedData($this->tsa, Oids::ID_CT_TST_INFO, $tstInfo, $genTime, $this->includeCertificate, $this->corruptSignature, $this->sign);
        $response = Asn1::sequence([Asn1::sequence([Asn1::integer(0)]), $token]);

        return new HttpResponse(200, ['Content-Type' => 'application/timestamp-reply'], $response);
    }
}
