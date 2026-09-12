<?php

declare(strict_types=1);

namespace Allkiri\Xades;

use Allkiri\Signing\SignatureLevel;

/**
 * What adding an archive timestamp produced.
 */
final readonly class LtaExtensionResult
{
    /**
     * @param int $archiveTimestampCount how many the signature now carries, this one included
     */
    public function __construct(
        public SignatureLevel $level,
        public \DateTimeImmutable $timestampTime,
        public int $archiveTimestampCount,
    ) {}
}
