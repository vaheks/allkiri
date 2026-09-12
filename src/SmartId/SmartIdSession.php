<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Exception\InvalidArgumentException;

/**
 * A Smart-ID operation waiting for the person to act.
 *
 * Everything the answer will be checked against is in here, which is why it
 * has to be stored rather than rebuilt: the challenge that was sent, the exact
 * interaction list that was sent, and for a device-link session the token and
 * secret that mint its links.
 *
 * It serialises to JSON for a session store or a database row. **A device-link
 * session contains the session secret, so the serialised form must stay on the
 * server**; sending it to a browser would let anyone mint links for this
 * session.
 */
final readonly class SmartIdSession implements \JsonSerializable
{
    public const VERSION = 1;

    public const TYPE_AUTHENTICATION = 'auth';
    public const TYPE_SIGNATURE = 'sign';

    /**
     * @param string      $challenge        the rpChallenge for an authentication, or the digest for a signature, raw bytes
     * @param string|null $verificationCode the code to show; notification flows get it from the service, device-link flows compute it
     */
    public function __construct(
        public string $sessionId,
        public string $type,
        public string $challenge,
        public Interactions $interactions,
        public ?string $verificationCode = null,
        public ?string $documentNumber = null,
        public ?string $sessionToken = null,
        public ?string $sessionSecret = null,
        public ?string $deviceLinkBase = null,
        public ?\DateTimeImmutable $startedAt = null,
    ) {
        if ($sessionId === '') {
            throw new InvalidArgumentException('A Smart-ID session needs an identifier');
        }
        if ($type !== self::TYPE_AUTHENTICATION && $type !== self::TYPE_SIGNATURE) {
            throw new InvalidArgumentException(\sprintf('Unknown Smart-ID session type "%s"', $type));
        }
        if ($challenge === '') {
            throw new InvalidArgumentException('A Smart-ID session needs the challenge or digest it was started with');
        }
    }

    /**
     * Whether this session is driven by a link rather than a push notification.
     */
    public function isDeviceLink(): bool
    {
        return $this->sessionSecret !== null;
    }

    /**
     * The challenge as the protocol carries it.
     */
    public function challengeBase64(): string
    {
        return base64_encode($this->challenge);
    }

    /**
     * Build a link for this session. Device-link sessions only.
     *
     * @param string   $scheme         the configuration's scheme name
     * @param int|null $elapsedSeconds seconds since the session started; QR links only.
     *                                 Computed from `startedAt` when omitted.
     */
    public function deviceLink(
        string $scheme,
        string $relyingPartyNameBase64,
        string $linkType = DeviceLink::TYPE_QR,
        string $language = 'eng',
        ?int $elapsedSeconds = null,
        ?string $initialCallbackUrl = null,
        ?\DateTimeImmutable $now = null,
    ): DeviceLink {
        if (!$this->isDeviceLink() || $this->sessionToken === null || $this->deviceLinkBase === null) {
            throw new InvalidArgumentException('This is a notification session; it has no device link');
        }

        return new DeviceLink(
            $scheme,
            $this->deviceLinkBase,
            $linkType,
            $this->type === self::TYPE_AUTHENTICATION ? DeviceLink::SESSION_AUTHENTICATION : DeviceLink::SESSION_SIGNATURE,
            $this->sessionToken,
            $relyingPartyNameBase64,
            $this->interactions->encoded,
            $this->challengeBase64(),
            $language,
            $initialCallbackUrl,
        );
    }

    /**
     * Seconds since the session started, for a QR link.
     */
    public function elapsedSeconds(?\DateTimeImmutable $now = null): int
    {
        if ($this->startedAt === null) {
            return 0;
        }

        return max(0, ($now ?? new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->getTimestamp() - $this->startedAt->getTimestamp());
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'version' => self::VERSION,
            'sessionId' => $this->sessionId,
            'type' => $this->type,
            'challenge' => base64_encode($this->challenge),
            'interactions' => $this->interactions->encoded,
            'verificationCode' => $this->verificationCode,
            'documentNumber' => $this->documentNumber,
            'sessionToken' => $this->sessionToken,
            'sessionSecret' => $this->sessionSecret,
            'deviceLinkBase' => $this->deviceLinkBase,
            'startedAt' => $this->startedAt?->format(DATE_ATOM),
        ];
    }

    /**
     * @param array<mixed> $data
     */
    public static function fromArray(array $data): self
    {
        if (($data['version'] ?? null) !== self::VERSION) {
            throw new InvalidArgumentException('Unsupported Smart-ID session version');
        }
        $challenge = base64_decode(self::string($data, 'challenge'), true);
        if ($challenge === false) {
            throw new InvalidArgumentException('The stored Smart-ID challenge is not base64');
        }
        $startedAt = $data['startedAt'] ?? null;

        return new self(
            self::string($data, 'sessionId'),
            self::string($data, 'type'),
            $challenge,
            Interactions::fromEncoded(self::string($data, 'interactions')),
            self::optional($data, 'verificationCode'),
            self::optional($data, 'documentNumber'),
            self::optional($data, 'sessionToken'),
            self::optional($data, 'sessionSecret'),
            self::optional($data, 'deviceLinkBase'),
            \is_string($startedAt) ? new \DateTimeImmutable($startedAt) : null,
        );
    }

    public static function fromJson(string $json): self
    {
        $data = json_decode($json, true);
        if (!\is_array($data)) {
            throw new InvalidArgumentException('Smart-ID session JSON is not an object');
        }

        return self::fromArray($data);
    }

    /**
     * @param array<mixed> $data
     */
    private static function string(array $data, string $key): string
    {
        $value = $data[$key] ?? null;
        if (!\is_string($value) || $value === '') {
            throw new InvalidArgumentException(\sprintf('Smart-ID session is missing "%s"', $key));
        }

        return $value;
    }

    /**
     * @param array<mixed> $data
     */
    private static function optional(array $data, string $key): ?string
    {
        $value = $data[$key] ?? null;

        return \is_string($value) && $value !== '' ? $value : null;
    }
}
