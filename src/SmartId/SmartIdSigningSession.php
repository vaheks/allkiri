<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Signing\DataToBeSigned;
use Allkiri\StoredData;

/**
 * A signature half-made: the XAdES is built and the Smart-ID app is being asked
 * for the value.
 *
 * Serialise it between the request that started the signing and the one that
 * finishes it. A device-link session carries its session secret, so keep the
 * serialised form on the server.
 */
final readonly class SmartIdSigningSession implements \JsonSerializable
{
    public const VERSION = 1;

    public function __construct(
        public SmartIdSession $session,
        public DataToBeSigned $dataToBeSigned,
    ) {
        if ($session->type !== SmartIdSession::TYPE_SIGNATURE) {
            throw new InvalidArgumentException('A signing session must be of type signature');
        }
    }

    /**
     * The code to show the person, so they can compare it with their app.
     */
    public function verificationCode(): ?string
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
        return StoredData::restore($data, 'Smart-ID signing session', [self::VERSION], static fn(#[\SensitiveParameter] StoredData $stored): self => new self(
            SmartIdSession::fromArray($stored->object('session')),
            DataToBeSigned::fromArray($stored->object('dataToBeSigned')),
        ));
    }

    public static function fromJson(#[\SensitiveParameter] string $json): self
    {
        return self::fromArray(StoredData::decode($json, 'Smart-ID signing session'));
    }
}
