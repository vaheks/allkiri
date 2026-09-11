<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

/**
 * This person and phone number have no active Mobile-ID certificate, so there
 * is nothing to sign with.
 */
final class CertificateNotFoundException extends MobileIdException
{
    public function __construct(MobileIdIdentity $identity)
    {
        parent::__construct(\sprintf('No active Mobile-ID certificate for %s', $identity));
    }
}
