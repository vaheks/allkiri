<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Signing\DataToBeSigned;

/**
 * A signature half-made: the XAdES is built and the phone is being asked for
 * the value.
 *
 * Serialise it between the request that started the signing and the one that
 * finishes it. Nothing in it is secret, but it is bound to the container it
 * was prepared for and will not finalize against another.
 */
final readonly class MobileIdSigningSession implements \JsonSerializable
{
    public const VERSION = 1;

    public function __construct(
        public MobileIdSession $session,
        public DataToBeSigned $dataToBeSigned,
    ) {
        if ($session->type !== MobileIdSession::TYPE_SIGNATURE) {
            throw new InvalidArgumentException('A signing session must be of type signature');
        }
    }

    /**
     * The four digits to show the person, so they can compare them with their
     * phone before entering PIN2.
     */
    public function verificationCode(): string
    {
        return $this->session->verificationCode;
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'version' => self::VERSION,
            'session' => $this->session->jsonSerialize(),
            'dataToBeSigned' => $this->dataToBeSigned->jsonSerialize(),
        ];
    }

    /**
     * @param array<mixed> $data
     */
    public static function fromArray(array $data): self
    {
        if (($data['version'] ?? null) !== self::VERSION) {
            throw new InvalidArgumentException('Unsupported Mobile-ID signing session version');
        }
        $session = $data['session'] ?? null;
        $dataToBeSigned = $data['dataToBeSigned'] ?? null;
        if (!\is_array($session) || !\is_array($dataToBeSigned)) {
            throw new InvalidArgumentException('A Mobile-ID signing session needs both the session and the data to be signed');
        }

        return new self(MobileIdSession::fromArray($session), DataToBeSigned::fromArray($dataToBeSigned));
    }

    public static function fromJson(string $json): self
    {
        $data = json_decode($json, true);
        if (!\is_array($data)) {
            throw new InvalidArgumentException('Mobile-ID signing session JSON is not an object');
        }

        return self::fromArray($data);
    }
}
