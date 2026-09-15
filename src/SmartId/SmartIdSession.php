<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\StoredData;

/**
 * A Smart-ID operation waiting for the person to act.
 *
 * Everything the answer will be checked against is in here, which is why it
 * has to be stored rather than rebuilt: the challenge that was sent, the exact
 * interaction list that was sent, the callback URL a same-device flow returns
 * to, the certificate level and the account or person that were asked for,
 * and for a device-link session the token and secret that mint its links.
 *
 * It serialises to JSON for a session store or a database row. **A device-link
 * session contains the session secret, so the serialised form must stay on the
 * server**; sending it to a browser would let anyone mint links for this
 * session.
 */
final readonly class SmartIdSession implements \JsonSerializable
{
    public const VERSION = 2;

    /**
     * Sessions stored before the callback URL, the requested level and the
     * person asked for were kept. They are still read, so that a deploy does
     * not end the sessions in flight; they live two minutes.
     */
    private const VERSION_1 = 1;

    public const TYPE_AUTHENTICATION = 'auth';
    public const TYPE_SIGNATURE = 'sign';

    /**
     * @param string                   $challenge           the rpChallenge for an authentication, or the digest for a signature, raw bytes
     * @param string|null              $verificationCode    the code to show; notification flows get it from the service, device-link flows compute it
     * @param string|null              $documentNumber      the account the session was started for, when it was started for one
     * @param string|null              $initialCallbackUrl  where a Web2App or App2App flow sends the person back; the app signs it, and every
     *                                                      link's authentication code covers it
     * @param CertificateLevel|null    $certificateLevel    the level the session asked for; null for a session stored before it was kept
     * @param SemanticsIdentifier|null $semanticsIdentifier the person the session was started for, when it was started for a person
     */
    public function __construct(
        public string $sessionId,
        public string $type,
        public string $challenge,
        public Interactions $interactions,
        public ?string $verificationCode = null,
        public ?string $documentNumber = null,
        public ?string $sessionToken = null,
        #[\SensitiveParameter]
        public ?string $sessionSecret = null,
        public ?string $deviceLinkBase = null,
        public ?\DateTimeImmutable $startedAt = null,
        public ?string $initialCallbackUrl = null,
        public ?CertificateLevel $certificateLevel = null,
        public ?SemanticsIdentifier $semanticsIdentifier = null,
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
        if ($documentNumber !== null && $semanticsIdentifier !== null) {
            throw new InvalidArgumentException('A Smart-ID session is started for an account or for a person, not both');
        }
        self::requireUsableCallbackUrl($initialCallbackUrl);
    }

    /**
     * Refuse a callback URL that would make what the app signs ambiguous.
     *
     * The URL is one of the pipe-separated fields of the signed payload and of
     * every link's authentication code, so a "|" inside it would shift the
     * fields after it.
     *
     * @throws InvalidArgumentException
     */
    public static function requireUsableCallbackUrl(?string $initialCallbackUrl): void
    {
        if ($initialCallbackUrl === null) {
            return;
        }
        if ($initialCallbackUrl === '' || str_contains($initialCallbackUrl, '|')) {
            throw new InvalidArgumentException('The callback URL must not be empty or contain "|", which separates the fields the app signs');
        }
        if (!mb_check_encoding($initialCallbackUrl, 'UTF-8')) {
            throw new InvalidArgumentException('The callback URL must be UTF-8');
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
     * A Web2App or App2App link carries the callback URL the session was
     * started with, because its authentication code covers it. A QR link
     * carries none, as the protocol requires: the person is on another device.
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
            $linkType === DeviceLink::TYPE_QR ? null : $this->initialCallbackUrl,
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
            'initialCallbackUrl' => $this->initialCallbackUrl,
            'certificateLevel' => $this->certificateLevel?->value,
            'semanticsIdentifier' => $this->semanticsIdentifier === null ? null : (string) $this->semanticsIdentifier,
        ];
    }

    /**
     * @param array<mixed> $data
     */
    public static function fromArray(#[\SensitiveParameter] array $data): self
    {
        return StoredData::restore($data, 'Smart-ID session', [self::VERSION, self::VERSION_1], static function (#[\SensitiveParameter] StoredData $stored): self {
            // Only version 2 has anything to read in these.
            $v2 = $stored->version === self::VERSION;
            $semanticsIdentifier = $v2 ? $stored->optionalString('semanticsIdentifier') : null;

            return new self(
                $stored->string('sessionId'),
                $stored->string('type'),
                $stored->base64('challenge'),
                Interactions::fromEncoded($stored->string('interactions')),
                $stored->optionalString('verificationCode'),
                $stored->optionalString('documentNumber'),
                $stored->optionalString('sessionToken'),
                $stored->optionalString('sessionSecret'),
                $stored->optionalString('deviceLinkBase'),
                $stored->optionalDate('startedAt'),
                $v2 ? $stored->optionalString('initialCallbackUrl') : null,
                $v2 ? $stored->optionalEnum('certificateLevel', CertificateLevel::class) : null,
                $semanticsIdentifier === null ? null : SemanticsIdentifier::parse($semanticsIdentifier),
            );
        });
    }

    /**
     * @throws \Allkiri\Exception\SessionDataException when what was stored cannot be read back
     */
    public static function fromJson(#[\SensitiveParameter] string $json): self
    {
        return self::fromArray(StoredData::decode($json, 'Smart-ID session'));
    }
}
