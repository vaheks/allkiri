<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

/**
 * The service could not be reached, refused the request, or answered with
 * something unreadable. These are faults on our side or SK's, never the
 * person's: a wrong relying-party identifier, a malformed request, an outage.
 */
final class MobileIdApiException extends MobileIdException
{
    public const REASON_TRANSPORT = 'MID_TRANSPORT';
    public const REASON_BAD_REQUEST = 'MID_BAD_REQUEST';
    public const REASON_UNAUTHORISED = 'MID_UNAUTHORISED';
    public const REASON_SESSION_NOT_FOUND = 'MID_SESSION_NOT_FOUND';
    public const REASON_RATE_LIMITED = 'MID_RATE_LIMITED';
    public const REASON_SERVER_ERROR = 'MID_SERVER_ERROR';
    public const REASON_MALFORMED_RESPONSE = 'MID_MALFORMED_RESPONSE';

    public function __construct(
        public readonly string $reason,
        string $message,
        public readonly ?int $status = null,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    public static function forStatus(int $status, string $url, string $body): self
    {
        [$reason, $explanation] = match ($status) {
            400 => [self::REASON_BAD_REQUEST, 'the request was rejected as malformed'],
            401 => [self::REASON_UNAUTHORISED, 'the relying party identifier or name was not accepted'],
            403 => [self::REASON_UNAUTHORISED, 'the relying party is not allowed to make this request'],
            404 => [self::REASON_SESSION_NOT_FOUND, 'the session is unknown; sessions are forgotten five minutes after they end'],
            405 => [self::REASON_BAD_REQUEST, 'the method is not allowed on this endpoint'],
            429 => [self::REASON_RATE_LIMITED, 'the relying party has made too many requests'],
            471 => [self::REASON_UNAUTHORISED, 'no suitable account of the requested type was found'],
            472 => [self::REASON_UNAUTHORISED, 'the person should view a notice in the Mobile-ID application'],
            480 => [self::REASON_BAD_REQUEST, 'the client is too old and no longer supported'],
            580 => [self::REASON_SERVER_ERROR, 'the system is under maintenance'],
            default => [$status >= 500 ? self::REASON_SERVER_ERROR : self::REASON_BAD_REQUEST, 'the service answered unexpectedly'],
        };

        return new self($reason, \sprintf('Mobile-ID at %s answered HTTP %d: %s%s', $url, $status, $explanation, self::detail($body)), $status);
    }

    private static function detail(string $body): string
    {
        $trimmed = trim(mb_substr($body, 0, 300));

        return $trimmed === '' ? '' : ' (' . $trimmed . ')';
    }
}
