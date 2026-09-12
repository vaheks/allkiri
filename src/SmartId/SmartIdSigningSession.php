<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Signing\DataToBeSigned;

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
    public static function fromArray(array $data): self
    {
        if (($data['version'] ?? null) !== self::VERSION) {
            throw new InvalidArgumentException('Unsupported Smart-ID signing session version');
        }
        $session = $data['session'] ?? null;
        $dataToBeSigned = $data['dataToBeSigned'] ?? null;
        if (!\is_array($session) || !\is_array($dataToBeSigned)) {
            throw new InvalidArgumentException('A Smart-ID signing session needs both the session and the data to be signed');
        }

        return new self(SmartIdSession::fromArray($session), DataToBeSigned::fromArray($dataToBeSigned));
    }

    public static function fromJson(string $json): self
    {
        $data = json_decode($json, true);
        if (!\is_array($data)) {
            throw new InvalidArgumentException('Smart-ID signing session JSON is not an object');
        }

        return self::fromArray($data);
    }
}
