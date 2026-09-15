<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\StoredData;

/**
 * A Mobile-ID operation waiting for the person to act.
 *
 * It carries the verification code, which must be shown so the person can
 * compare it with their phone, and it serialises to JSON so a web application
 * can keep it between requests.
 */
final readonly class MobileIdSession implements \JsonSerializable
{
    public const VERSION = 1;

    public const TYPE_AUTHENTICATION = 'authentication';
    public const TYPE_SIGNATURE = 'signature';

    /**
     * @param string $type      one of the TYPE_ constants; decides which endpoint is polled
     * @param string $challenge for authentication, the bytes whose hash was sent, kept so
     *                          the answer can be verified; empty for signing
     */
    public function __construct(
        public string $sessionId,
        public string $type,
        public string $verificationCode,
        public MobileIdIdentity $identity,
        public string $challenge = '',
    ) {
        if ($sessionId === '') {
            throw new InvalidArgumentException('A Mobile-ID session needs an identifier');
        }
        if ($type !== self::TYPE_AUTHENTICATION && $type !== self::TYPE_SIGNATURE) {
            throw new InvalidArgumentException(\sprintf('Unknown Mobile-ID session type "%s"', $type));
        }
    }

    /**
     * @return array<string, string|int>
     */
    public function jsonSerialize(): array
    {
        return [
            'version' => self::VERSION,
            'sessionId' => $this->sessionId,
            'type' => $this->type,
            'verificationCode' => $this->verificationCode,
            'phoneNumber' => $this->identity->phoneNumber,
            'nationalIdentityNumber' => $this->identity->nationalIdentityNumber,
            'challenge' => base64_encode($this->challenge),
        ];
    }

    /**
     * @param array<mixed> $data
     */
    public static function fromArray(#[\SensitiveParameter] array $data): self
    {
        return StoredData::restore($data, 'Mobile-ID session', [self::VERSION], static fn(#[\SensitiveParameter] StoredData $stored): self => new self(
            $stored->string('sessionId'),
            $stored->string('type'),
            $stored->string('verificationCode'),
            new MobileIdIdentity($stored->string('phoneNumber'), $stored->string('nationalIdentityNumber')),
            // A signing session stores an empty challenge.
            $stored->base64('challenge', allowEmpty: true),
        ));
    }

    public static function fromJson(#[\SensitiveParameter] string $json): self
    {
        return self::fromArray(StoredData::decode($json, 'Mobile-ID session'));
    }
}
