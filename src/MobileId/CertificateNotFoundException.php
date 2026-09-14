<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

/**
 * This person and phone number have no active Mobile-ID certificate, so there
 * is nothing to sign with.
 *
 * The message does not name them. Exceptions end up in logs, and whether a
 * given person has Mobile-ID is itself personal data. The identity is kept on
 * the exception for an application that needs it.
 */
final class CertificateNotFoundException extends MobileIdException
{
    /**
     * @param string $result what the service answered instead of OK; NOT_FOUND is the documented answer
     */
    public function __construct(
        public readonly MobileIdIdentity $identity,
        public readonly string $result = 'NOT_FOUND',
    ) {
        parent::__construct(\sprintf('No active Mobile-ID certificate for this phone number and identity code (%s)', $result));
    }
}
