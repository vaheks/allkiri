<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

use Allkiri\Exception\InvalidArgumentException;

/**
 * Who we are to SK, and what the person sees on their phone.
 *
 * The relying-party identifier and name are issued with a contract. The demo
 * pair below is public and works only against the demo service.
 */
final readonly class MobileIdConfiguration
{
    public const DEMO_URL = 'https://tsp.demo.sk.ee/mid-api';
    public const PRODUCTION_URL = 'https://mid.sk.ee/mid-api';

    public const DEMO_RELYING_PARTY_UUID = '00000000-0000-0000-0000-000000000000';
    public const DEMO_RELYING_PARTY_NAME = 'DEMO';

    /** Above this the service silently uses its own maximum instead. */
    public const MAX_POLL_TIMEOUT_MS = 60_000;

    /**
     * How much longer than the poll timeout the HTTP client must be willing to
     * wait: the request and the response still have to cross the network.
     */
    public const HTTP_TIMEOUT_MARGIN_SECONDS = 5;

    /**
     * @param string $displayText     shown on the phone above the verification code
     * @param int    $pollTimeoutMs   how long the service may hold one status request open
     * @param int    $sessionTimeoutSeconds how long to keep asking before giving up on the person
     */
    public function __construct(
        public string $url,
        public string $relyingPartyUuid,
        public string $relyingPartyName,
        public MobileIdLanguage $language = MobileIdLanguage::Estonian,
        public string $displayText = '',
        public DisplayTextFormat $displayTextFormat = DisplayTextFormat::Gsm7,
        public int $pollTimeoutMs = 10_000,
        public int $sessionTimeoutSeconds = 120,
    ) {
        if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $relyingPartyUuid) !== 1) {
            throw new InvalidArgumentException('The relying party identifier must be a lower-case UUID in 8-4-4-4-12 form');
        }
        if ($relyingPartyName === '') {
            throw new InvalidArgumentException('The relying party name must not be empty');
        }
        if ($displayText !== '') {
            if ($displayTextFormat->lengthOf($displayText) > $displayTextFormat->maximumLength()) {
                throw new InvalidArgumentException(\sprintf(
                    'The display text is longer than %s allows (%d of %d characters)',
                    $displayTextFormat->value,
                    $displayTextFormat->lengthOf($displayText),
                    $displayTextFormat->maximumLength(),
                ));
            }
            // The service replaces these with spaces rather than refusing them,
            // so the person would just see a mangled sentence. Estonian õ, š
            // and ž are the usual casualties; UCS-2 carries them.
            $unsupported = $displayTextFormat->unsupportedCharacters($displayText);
            if ($unsupported !== []) {
                throw new InvalidArgumentException(\sprintf(
                    'The display text contains %s that %s cannot carry: the service would replace them with spaces. Use DisplayTextFormat::Ucs2.',
                    implode(', ', array_map(static fn(string $c): string => '"' . $c . '"', $unsupported)),
                    $displayTextFormat->value,
                ));
            }
            if ($displayTextFormat->exceedsExtensionLimit($displayText)) {
                throw new InvalidArgumentException('The display text uses more than the five extension-table characters GSM-7 allows');
            }
        }
        // Larger values are silently reverted by the service, and the HTTP
        // client must be given longer than this to answer.
        if ($pollTimeoutMs < 1_000 || $pollTimeoutMs > self::MAX_POLL_TIMEOUT_MS) {
            throw new InvalidArgumentException(\sprintf('The poll timeout must be between 1000 and %d milliseconds', self::MAX_POLL_TIMEOUT_MS));
        }
        if ($sessionTimeoutSeconds < 1) {
            throw new InvalidArgumentException('The session timeout must be at least one second');
        }
    }

    /**
     * The public demo service. Only the published test numbers answer on it.
     */
    public static function demo(string $displayText = '', MobileIdLanguage $language = MobileIdLanguage::Estonian): self
    {
        return new self(self::DEMO_URL, self::DEMO_RELYING_PARTY_UUID, self::DEMO_RELYING_PARTY_NAME, $language, $displayText);
    }

    public static function production(string $relyingPartyUuid, string $relyingPartyName, string $displayText = '', MobileIdLanguage $language = MobileIdLanguage::Estonian): self
    {
        return new self(self::PRODUCTION_URL, $relyingPartyUuid, $relyingPartyName, $language, $displayText);
    }

    public function isDemo(): bool
    {
        return $this->relyingPartyUuid === self::DEMO_RELYING_PARTY_UUID;
    }

    /**
     * The shortest HTTP timeout that will not cut a long poll short.
     */
    public function httpTimeoutSeconds(): int
    {
        return (int) ceil($this->pollTimeoutMs / 1000) + self::HTTP_TIMEOUT_MARGIN_SECONDS;
    }

    public function withDisplayText(string $text, DisplayTextFormat $format = DisplayTextFormat::Gsm7): self
    {
        return new self($this->url, $this->relyingPartyUuid, $this->relyingPartyName, $this->language, $text, $format, $this->pollTimeoutMs, $this->sessionTimeoutSeconds);
    }

    public function withLanguage(MobileIdLanguage $language): self
    {
        return new self($this->url, $this->relyingPartyUuid, $this->relyingPartyName, $language, $this->displayText, $this->displayTextFormat, $this->pollTimeoutMs, $this->sessionTimeoutSeconds);
    }

    public function withTimeouts(int $pollTimeoutMs, int $sessionTimeoutSeconds): self
    {
        return new self($this->url, $this->relyingPartyUuid, $this->relyingPartyName, $this->language, $this->displayText, $this->displayTextFormat, $pollTimeoutMs, $sessionTimeoutSeconds);
    }
}
