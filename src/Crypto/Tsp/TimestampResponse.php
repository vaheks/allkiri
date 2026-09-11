<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Tsp;

use Allkiri\Crypto\Asn1\Asn1;
use Allkiri\Crypto\Asn1\Asn1Exception;
use Allkiri\Crypto\Asn1\Maps\TspMaps;
use phpseclib3\Math\BigInteger;

/**
 * An RFC 3161 TimeStampResp: status plus, when granted, the token.
 */
final class TimestampResponse
{
    private readonly PkiStatus $status;

    /** @var list<string> */
    private readonly array $statusText;

    private readonly ?TimestampToken $token;

    private function __construct(private readonly string $der)
    {
        $decoded = Asn1::decode($der, TspMaps::TIME_STAMP_RESP);
        $status = $decoded->get('status', 'status');
        if (!$status instanceof BigInteger) {
            throw new Asn1Exception('Malformed PKIStatusInfo');
        }
        $this->status = PkiStatus::tryFrom((int) $status->toString()) ?? throw new Asn1Exception('Unknown PKIStatus ' . $status->toString());
        $text = [];
        foreach ((array) $decoded->get('status', 'statusString') as $line) {
            if (\is_string($line)) {
                $text[] = $line;
            }
        }
        $this->statusText = $text;

        $tokenNode = $decoded->has('timeStampToken') ? $decoded->node()->child(1) : null;
        $this->token = $tokenNode === null ? null : TimestampToken::fromDer($tokenNode->der());
    }

    public static function fromDer(string $der): self
    {
        return new self($der);
    }

    public function der(): string
    {
        return $this->der;
    }

    public function status(): PkiStatus
    {
        return $this->status;
    }

    /**
     * @return list<string> the TSA's free-text status lines
     */
    public function statusText(): array
    {
        return $this->statusText;
    }

    public function token(): ?TimestampToken
    {
        return $this->token;
    }
}
