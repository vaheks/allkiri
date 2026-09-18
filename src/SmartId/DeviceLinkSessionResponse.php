<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Http\HttpRequest;

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
        #[\SensitiveParameter]
        public string $sessionSecret,
        public string $deviceLinkBase,
    ) {}

    /**
     * @param array<string, mixed> $body
     */
    public static function fromArray(#[\SensitiveParameter] array $body): self
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
        self::requireUsableDeviceLinkBase($body['deviceLinkBase']);

        return new self($body['sessionID'], $body['sessionToken'], $body['sessionSecret'], $body['deviceLinkBase']);
    }

    /**
     * Refuse a base that is not an address a link can be built on.
     *
     * Every link this session mints starts with these bytes, and an application
     * puts the finished link in a QR code, in an anchor's href and in
     * `location.href` — the demo does all three. A base carrying a scheme such
     * as `javascript:` would therefore not be a link to the Smart-ID app but
     * script running on the relying party's own page.
     *
     * SK returns an https address here. This checks it, rather than trusting
     * that it always will, because it is the one value in this response that a
     * browser is asked to follow.
     *
     * @throws SmartIdApiException
     */
    private static function requireUsableDeviceLinkBase(string $deviceLinkBase): void
    {
        try {
            HttpRequest::requireHttps($deviceLinkBase, 'The device link address Smart-ID returned');
        } catch (InvalidArgumentException $e) {
            throw new SmartIdApiException(SmartIdApiException::REASON_MALFORMED_RESPONSE, $e->getMessage(), previous: $e);
        }
    }
}
