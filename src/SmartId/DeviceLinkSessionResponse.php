<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

/**
 * What the service returns when a device-link session starts.
 *
 * The session secret is the key that authenticates every link built from this
 * session. **It must never leave the server**: anyone holding it can mint links
 * the app will accept for this session.
 */
final readonly class DeviceLinkSessionResponse
{
    public function __construct(
        public string $sessionId,
        public string $sessionToken,
        public string $sessionSecret,
        public string $deviceLinkBase,
    ) {}

    /**
     * @param array<string, mixed> $body
     */
    public static function fromArray(array $body): self
    {
        foreach (['sessionID', 'sessionToken', 'sessionSecret', 'deviceLinkBase'] as $key) {
            if (!\is_string($body[$key] ?? null) || $body[$key] === '') {
                throw new SmartIdApiException(
                    SmartIdApiException::REASON_MALFORMED_RESPONSE,
                    \sprintf('Smart-ID started a device-link session without "%s"', $key),
                );
            }
        }

        /** @var array{sessionID: string, sessionToken: string, sessionSecret: string, deviceLinkBase: string} $body */
        return new self($body['sessionID'], $body['sessionToken'], $body['sessionSecret'], $body['deviceLinkBase']);
    }
}
