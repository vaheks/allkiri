<?php

declare(strict_types=1);

namespace Allkiri\Trust;

use Allkiri\Crypto\Certificate;
use Allkiri\Trust\TrustedList\TrustedListStatus;

/**
 * A certificate that is trusted for a service type, with the status history
 * a trusted list records for it (or a single "granted since forever" entry
 * for manually configured anchors).
 */
final readonly class TrustAnchor
{
    /** @var list<array{status: ServiceStatus, since: \DateTimeImmutable}> ascending by time */
    public array $statusHistory;

    /**
     * @param list<array{status: ServiceStatus, since: \DateTimeImmutable}> $statusHistory
     * @param TrustedListStatus|null                                        $trustedList   the list that published the anchor; null for one configured by hand, which never expires
     */
    public function __construct(
        public Certificate $certificate,
        public ServiceType $serviceType,
        public string $serviceName,
        array $statusHistory,
        public string $source,
        public ?TrustedListStatus $trustedList = null,
    ) {
        usort($statusHistory, static fn(array $a, array $b): int => $a['since'] <=> $b['since']);
        $this->statusHistory = $statusHistory;
    }

    public function withTrustedList(TrustedListStatus $trustedList): self
    {
        return new self($this->certificate, $this->serviceType, $this->serviceName, $this->statusHistory, $this->source, $trustedList);
    }

    /**
     * An anchor configured by hand rather than read from a trusted list.
     */
    public static function manual(Certificate $certificate, ServiceType $serviceType, string $serviceName = '', string $source = 'manual'): self
    {
        return new self($certificate, $serviceType, $serviceName !== '' ? $serviceName : ($certificate->commonName() ?? ''), [
            ['status' => ServiceStatus::Granted, 'since' => new \DateTimeImmutable('@0')],
        ], $source);
    }

    /**
     * The status in force at the given time, or null before the first entry.
     */
    public function statusAt(\DateTimeInterface $time): ?ServiceStatus
    {
        $status = null;
        foreach ($this->statusHistory as $entry) {
            if ($entry['since'] <= $time) {
                $status = $entry['status'];
            }
        }

        return $status;
    }

    public function isTrustworthyAt(\DateTimeInterface $time): bool
    {
        return $this->statusAt($time)?->isTrustworthy() ?? false;
    }

    public function currentStatus(): ?ServiceStatus
    {
        $last = $this->statusHistory[\count($this->statusHistory) - 1] ?? null;

        return $last['status'] ?? null;
    }
}
