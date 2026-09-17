<?php

declare(strict_types=1);

namespace Allkiri\Validation\Siva;

use Allkiri\Exception\AllkiriException;

/**
 * SiVa could not be asked, could not be reached, or did not answer in a way we
 * can read. `reason` says which, as one of the REASON_* constants.
 */
final class SivaException extends \RuntimeException implements AllkiriException
{
    /** The request could not be built, such as a file name that is not UTF-8. Nothing was sent. */
    public const REASON_REQUEST = 'SIVA_REQUEST_INVALID';

    /** SiVa could not be reached. */
    public const REASON_TRANSPORT = 'SIVA_TRANSPORT';

    /**
     * Bot protection in front of SiVa answered with a challenge page instead of
     * a verdict. Usually passes on a later try; a server refused every time
     * is a question for RIA, which runs the service.
     */
    public const REASON_CHALLENGED = 'SIVA_CHALLENGED';

    /** SiVa answered with a status other than success. */
    public const REASON_HTTP_STATUS = 'SIVA_HTTP_STATUS';

    /** SiVa answered with something that is not a validation report. */
    public const REASON_MALFORMED = 'SIVA_MALFORMED';

    public function __construct(
        public readonly string $reason,
        string $message,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
