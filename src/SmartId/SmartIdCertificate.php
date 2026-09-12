<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Crypto\Certificate;

/**
 * A certificate the service handed over, with the level it certified it at and
 * the account it belongs to.
 */
final readonly class SmartIdCertificate
{
    public function __construct(
        public Certificate $certificate,
        public CertificateLevel $level,
        public DocumentNumber $documentNumber,
    ) {}
}
