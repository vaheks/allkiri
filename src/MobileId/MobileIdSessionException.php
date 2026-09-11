<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

/**
 * The session ended without a signature, for a reason the person can usually
 * understand: they cancelled, the phone was off, they have no Mobile-ID.
 *
 * Show `$result->message()` rather than this exception's text.
 */
final class MobileIdSessionException extends MobileIdException
{
    public function __construct(public readonly MobileIdResult $result)
    {
        parent::__construct(\sprintf('Mobile-ID session ended with %s: %s', $result->value, $result->message()));
    }
}
