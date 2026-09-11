<?php

declare(strict_types=1);

namespace Allkiri\Validation\Report;

enum Severity: string
{
    /** The signature cannot be accepted as it stands. */
    case Error = 'error';

    /** Worth telling the user, but the signature is still valid. */
    case Warning = 'warning';

    /** Context, not a problem. */
    case Info = 'info';
}
