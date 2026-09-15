<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Signing\DataToBeSigned;
use Allkiri\StoredData;

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
    public static function fromArray(#[\SensitiveParameter] array $data): self
    {
        return StoredData::restore($data, 'Mobile-ID signing session', [self::VERSION], static fn(#[\SensitiveParameter] StoredData $stored): self => new self(
            MobileIdSession::fromArray($stored->object('session')),
            DataToBeSigned::fromArray($stored->object('dataToBeSigned')),
        ));
    }

    /**
     * @throws \Allkiri\Exception\SessionDataException when what was stored cannot be read back
     */
    public static function fromJson(#[\SensitiveParameter] string $json): self
    {
        return self::fromArray(StoredData::decode($json, 'Mobile-ID signing session'));
    }
}
