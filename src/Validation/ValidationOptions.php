<?php

declare(strict_types=1);

namespace Allkiri\Validation;

use Allkiri\Trust\TrustStore;

final readonly class ValidationOptions
{
    /**
     * @param \DateTimeImmutable|null $validationTime pretend it is this moment (tests, or re-checking a past decision)
     * @param TrustStore|null         $trustStore     overrides the validator's own store
     */
    public function __construct(
        public ?\DateTimeImmutable $validationTime = null,
        public ?TrustStore $trustStore = null,
    ) {}
}
