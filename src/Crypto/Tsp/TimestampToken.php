<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Tsp;

use Allkiri\Crypto\Asn1\Asn1Exception;
use Allkiri\Crypto\Asn1\Oids;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\Cms\SignedData;
use Allkiri\Crypto\Cms\SignerInfo;

/**
 * A TimeStampToken: CMS SignedData over a TSTInfo. The DER is what a XAdES
 * EncapsulatedTimeStamp carries.
 */
final class TimestampToken
{
    private readonly SignedData $signedData;

    private readonly TstInfo $tstInfo;

    private function __construct(private readonly string $der)
    {
        $this->signedData = SignedData::fromDer($der);
        if ($this->signedData->eContentType() !== Oids::ID_CT_TST_INFO) {
            throw new Asn1Exception('Token content is not a TSTInfo');
        }
        $this->tstInfo = TstInfo::fromDer($this->signedData->eContent() ?? throw new Asn1Exception('Token has no TSTInfo content'));
    }

    public static function fromDer(string $der): self
    {
        return new self($der);
    }

    public function der(): string
    {
        return $this->der;
    }

    public function signedData(): SignedData
    {
        return $this->signedData;
    }

    public function tstInfo(): TstInfo
    {
        return $this->tstInfo;
    }

    public function genTime(): \DateTimeImmutable
    {
        return $this->tstInfo->genTime;
    }

    public function signerInfo(): SignerInfo
    {
        $infos = $this->signedData->signerInfos();
        if (\count($infos) !== 1) {
            throw new Asn1Exception(\sprintf('Timestamp token must have exactly one signer, has %d', \count($infos)));
        }

        return $infos[0];
    }

    /**
     * The TSA (TSU) certificate, resolved among the token's own certificates
     * and any extra candidates.
     *
     * @param list<Certificate> $extraCandidates
     */
    public function signerCertificate(array $extraCandidates = []): ?Certificate
    {
        return $this->signerInfo()->findSigner(array_merge($this->signedData->certificates(), $extraCandidates));
    }
}
