<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

/**
 * The session ended without a signature, for a reason the person can usually
 * understand.
 *
 * Show `$result->message()` rather than this exception's text.
 */
final class SmartIdSessionException extends SmartIdException
{
    /**
     * @param InteractionType|null $refusedInteraction which dialogue they refused,
     *                                                 when the service says so
     */
    public function __construct(
        public readonly SmartIdEndResult $result,
        public readonly ?InteractionType $refusedInteraction = null,
    ) {
        $where = $refusedInteraction === null ? '' : \sprintf(' at the %s dialogue', $refusedInteraction->value);
        parent::__construct(\sprintf('Smart-ID session ended with %s%s: %s', $result->value, $where, $result->message()));
    }
}
