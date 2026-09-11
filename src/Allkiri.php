<?php

declare(strict_types=1);

namespace Allkiri;

/**
 * Library identity. The only code that exists before Phase 1.
 */
final class Allkiri
{
    public const VERSION = '0.1.0-dev';

    /** Sent as User-Agent to SK, RIA and Zetes services so operators can identify the client. */
    public const USER_AGENT = 'allkiri/' . self::VERSION . ' (+https://github.com/vaheks/allkiri)';

    private function __construct() {}
}
