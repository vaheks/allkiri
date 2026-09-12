<?php

declare(strict_types=1);

namespace Allkiri\Trust\TrustedList;

use Allkiri\Crypto\Certificate;

/**
 * An OtherTSLPointer of a list of trusted lists: where another territory's
 * list lives and which certificates may sign it.
 */
final readonly class TrustedListPointer
{
    /** The machine-processable form of a trusted list. */
    public const MIME_XML = 'application/vnd.etsi.tsl+xml';

    /** The same list as a document for people to read. */
    public const MIME_PDF = 'application/pdf';

    /**
     * @param list<Certificate> $signingCertificates
     */
    public function __construct(
        public string $territory,
        public string $location,
        public array $signingCertificates,
        public ?string $mimeType = null,
    ) {}

    public function allows(Certificate $certificate): bool
    {
        foreach ($this->signingCertificates as $allowed) {
            if ($allowed->equals($certificate)) {
                return true;
            }
        }

        return false;
    }
}
