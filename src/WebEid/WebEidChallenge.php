<?php

declare(strict_types=1);

namespace Allkiri\WebEid;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\StoredData;

/**
 * The challenge a website hands the card, and the deadline for answering it.
 *
 * The Web eID application treats the nonce as an opaque string and signs the
 * hash of exactly those characters, so it must be stored and replayed verbatim
 * rather than decoded and re-encoded. The specification requires at least 32
 * bytes of entropy, which is 44 characters of base64, and at most 128
 * characters.
 *
 * Store it against the browser session that asked for it, and nothing else.
 * That binding is what stops someone from having a victim's browser log in with
 * an attacker's card: the token carries no nonce, so the server can only look
 * one up by the session it belongs to.
 */
final readonly class WebEidChallenge implements \JsonSerializable
{
    public const VERSION = 1;

    public const MINIMUM_LENGTH = 44;
    public const MAXIMUM_LENGTH = 128;

    public function __construct(
        public string $nonce,
        public \DateTimeImmutable $issuedAt,
        public \DateTimeImmutable $expiresAt,
    ) {
        $length = \strlen($nonce);
        if ($length < self::MINIMUM_LENGTH || $length > self::MAXIMUM_LENGTH) {
            throw new InvalidArgumentException(\sprintf(
                'A Web eID challenge must be between %d and %d characters, got %d',
                self::MINIMUM_LENGTH,
                self::MAXIMUM_LENGTH,
                $length,
            ));
        }
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('A Web eID challenge must expire after it was issued');
        }
    }

    public function isExpiredAt(\DateTimeInterface $now): bool
    {
        return $now > $this->expiresAt;
    }

    /**
     * @return array<string, string|int>
     */
    public function jsonSerialize(): array
    {
        return [
            'version' => self::VERSION,
            'nonce' => $this->nonce,
            'issuedAt' => $this->issuedAt->format(DATE_ATOM),
            'expiresAt' => $this->expiresAt->format(DATE_ATOM),
        ];
    }

    /**
     * @param array<mixed> $data
     */
    public static function fromArray(#[\SensitiveParameter] array $data): self
    {
        return StoredData::restore($data, 'Web eID challenge', [self::VERSION], static fn(#[\SensitiveParameter] StoredData $stored): self => new self(
            $stored->string('nonce'),
            $stored->date('issuedAt'),
            $stored->date('expiresAt'),
        ));
    }

    public static function fromJson(#[\SensitiveParameter] string $json): self
    {
        return self::fromArray(StoredData::decode($json, 'Web eID challenge'));
    }
}
