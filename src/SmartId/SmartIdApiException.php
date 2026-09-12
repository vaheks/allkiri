<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

/**
 * The service could not be reached, refused the request, or answered with
 * something unreadable.
 *
 * Most of these are configuration or account questions rather than anything
 * the person did wrong, which is why they are separate from
 * {@see SmartIdSessionException}.
 */
final class SmartIdApiException extends SmartIdException
{
    public const REASON_TRANSPORT = 'SID_TRANSPORT';
    public const REASON_BAD_REQUEST = 'SID_BAD_REQUEST';
    public const REASON_UNAUTHORISED = 'SID_UNAUTHORISED';
    public const REASON_ACCOUNT_NOT_FOUND = 'SID_ACCOUNT_NOT_FOUND';
    public const REASON_NO_SUITABLE_ACCOUNT = 'SID_NO_SUITABLE_ACCOUNT';
    public const REASON_SHOULD_VIEW_PORTAL = 'SID_SHOULD_VIEW_PORTAL';
    public const REASON_CLIENT_TOO_OLD = 'SID_CLIENT_TOO_OLD';
    public const REASON_RATE_LIMITED = 'SID_RATE_LIMITED';
    public const REASON_MAINTENANCE = 'SID_MAINTENANCE';
    public const REASON_SERVER_ERROR = 'SID_SERVER_ERROR';
    public const REASON_SESSION_NOT_FOUND = 'SID_SESSION_NOT_FOUND';
    public const REASON_MALFORMED_RESPONSE = 'SID_MALFORMED_RESPONSE';

    public function __construct(
        public readonly string $reason,
        string $message,
        public readonly ?int $status = null,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    /**
     * @param bool $isSessionRequest 404 means "no such session" when polling and
     *                               "no such account" when starting one
     */
    public static function forStatus(int $status, string $url, string $body, bool $isSessionRequest = false): self
    {
        [$reason, $explanation] = match ($status) {
            400 => [self::REASON_BAD_REQUEST, 'the request was rejected as malformed'],
            401 => [self::REASON_UNAUTHORISED, 'the relying party identifier or name was not accepted'],
            403 => [self::REASON_UNAUTHORISED, 'the relying party is not allowed to make this request, which is also what an ADVANCED request with the wrong identifier looks like'],
            404 => $isSessionRequest
                ? [self::REASON_SESSION_NOT_FOUND, 'the session is unknown; sessions are forgotten shortly after they end']
                : [self::REASON_ACCOUNT_NOT_FOUND, 'the person has no Smart-ID account of the requested kind'],
            429 => [self::REASON_RATE_LIMITED, 'the relying party has made too many requests'],
            471 => [self::REASON_NO_SUITABLE_ACCOUNT, 'the person has Smart-ID accounts but none of the requested kind'],
            472 => [self::REASON_SHOULD_VIEW_PORTAL, 'the person must open the Smart-ID app or the self-service portal before this will work'],
            480 => [self::REASON_CLIENT_TOO_OLD, 'this client version is no longer supported by the service'],
            580 => [self::REASON_MAINTENANCE, 'the system is under maintenance'],
            default => [$status >= 500 ? self::REASON_SERVER_ERROR : self::REASON_BAD_REQUEST, 'the service answered unexpectedly'],
        };

        return new self($reason, \sprintf('Smart-ID at %s answered HTTP %d: %s%s', $url, $status, $explanation, self::detail($body)), $status);
    }

    private static function detail(string $body): string
    {
        $trimmed = trim(mb_substr($body, 0, 300));

        return $trimmed === '' ? '' : ' (' . $trimmed . ')';
    }
}
