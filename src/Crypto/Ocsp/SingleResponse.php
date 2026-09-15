<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Ocsp;

use Allkiri\Crypto\Asn1\Asn1Exception;
use Allkiri\Crypto\Asn1\Node;

/**
 * One SingleResponse of a BasicOCSPResponse (RFC 6960 §4.2.1).
 */
final readonly class SingleResponse
{
    public function __construct(
        public CertId $certId,
        public CertStatus $status,
        public \DateTimeImmutable $thisUpdate,
        public ?\DateTimeImmutable $nextUpdate,
        public ?\DateTimeImmutable $revokedAt,
        public ?string $revocationReason,
    ) {}

    /**
     * @param array<mixed> $mapped asn1map output of one SingleResponse
     * @param Node         $node   the same element, for exact times
     *
     * @internal
     */
    public static function fromMapped(array $mapped, Node $node): self
    {
        $certId = $mapped['certID'] ?? null;
        $statusChoice = $mapped['certStatus'] ?? null;
        if (!\is_array($certId) || !\is_array($statusChoice)) {
            throw new Asn1Exception('Malformed SingleResponse');
        }
        $statusKey = array_key_first($statusChoice);
        $status = CertStatus::tryFrom(\is_string($statusKey) ? $statusKey : '') ?? throw new Asn1Exception('Malformed certStatus');

        $revokedAt = null;
        $reason = null;
        if ($status === CertStatus::Revoked) {
            $info = $statusChoice['revoked'];
            $revokedAt = $node->child(1)->child(0)->time();
            $reasonValue = \is_array($info) ? ($info['revocationReason'] ?? null) : null;
            $reason = \is_string($reasonValue) ? $reasonValue : null;
        }

        $thisUpdate = $node->child(2)->time();
        // certStatus "good" is itself a [0]-tagged element, so look for nextUpdate only after thisUpdate.
        $nextUpdate = null;
        foreach (\array_slice($node->children(), 3) as $trailing) {
            if ($trailing->isTagged() && $trailing->tag() === 0) {
                $nextUpdate = $trailing->child(0)->time();
            }
        }

        return new self(CertId::fromMapped($certId), $status, $thisUpdate, $nextUpdate, $revokedAt, $reason);
    }
}
