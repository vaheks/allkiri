<?php

declare(strict_types=1);

namespace Allkiri\Trust;

use Allkiri\Crypto\Certificate;

/**
 * A verified path from a leaf certificate up to a trust anchor.
 */
final readonly class CertificateChain
{
    /** @var non-empty-list<Certificate> leaf first, anchor certificate last */
    public array $certificates;

    /**
     * @param non-empty-list<Certificate> $certificates leaf first, anchor certificate last
     */
    public function __construct(array $certificates, public TrustAnchor $anchor)
    {
        $this->certificates = $certificates;
    }

    public function leaf(): Certificate
    {
        return $this->certificates[0];
    }

    /**
     * The certificate that issued the leaf; the leaf itself when it is the anchor.
     */
    public function issuerOfLeaf(): Certificate
    {
        return $this->certificates[1] ?? $this->certificates[0];
    }

    /**
     * Everything above the leaf, root included.
     *
     * @return list<Certificate>
     */
    public function caCertificates(): array
    {
        return \array_slice($this->certificates, 1);
    }

    public function length(): int
    {
        return \count($this->certificates);
    }

    public function contains(Certificate $certificate): bool
    {
        foreach ($this->certificates as $member) {
            if ($member->equals($certificate)) {
                return true;
            }
        }

        return false;
    }
}
