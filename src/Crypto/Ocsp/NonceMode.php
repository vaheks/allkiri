<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Ocsp;

/**
 * How strictly the OCSP nonce is enforced. SK's responders echo nonces; some
 * AIA responders serve pre-produced responses and cannot.
 */
enum NonceMode
{
    /** The response must carry the request's nonce. */
    case Required;

    /** A nonce in the response must match; a missing one is tolerated. */
    case IfPresent;

    /** Nonces are neither sent nor checked (freshness rests on producedAt). */
    case Ignore;
}
