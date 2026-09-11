<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

use Allkiri\Exception\InvalidArgumentException;

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
    public static function fromArray(array $data): self
    {
        if (($data['version'] ?? null) !== self::VERSION) {
            throw new InvalidArgumentException('Unsupported Mobile-ID session version');
        }
        $challenge = base64_decode(self::string($data, 'challenge', ''), true);

        return new self(
            self::string($data, 'sessionId'),
            self::string($data, 'type'),
            self::string($data, 'verificationCode'),
            new MobileIdIdentity(self::string($data, 'phoneNumber'), self::string($data, 'nationalIdentityNumber')),
            $challenge === false ? '' : $challenge,
        );
    }

    public static function fromJson(string $json): self
    {
        $data = json_decode($json, true);
        if (!\is_array($data)) {
            throw new InvalidArgumentException('Mobile-ID session JSON is not an object');
        }

        return self::fromArray($data);
    }

    /**
     * @param array<mixed> $data
     */
    private static function string(array $data, string $key, ?string $default = null): string
    {
        $value = $data[$key] ?? $default;
        if (!\is_string($value)) {
            throw new InvalidArgumentException(\sprintf('Mobile-ID session is missing "%s"', $key));
        }

        return $value;
    }
}
