<?php

declare(strict_types=1);

namespace Allkiri\WebEid;

use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Signing\DataToBeSigned;

/**
 * A signature half-made: the XAdES is built and the browser is being asked for
 * the value.
 *
 * Everything the page needs is in {@see forBrowser()}; the rest has to be kept
 * server-side and handed back to finish the signature.
 */
final readonly class WebEidSigningSession implements \JsonSerializable
{
    public const VERSION = 1;

    public function __construct(
        public DataToBeSigned $dataToBeSigned,
        public CardAlgorithm $algorithm,
    ) {}

    /**
     * What to send the page, which passes it straight to `webeid.sign()`.
     *
     * @return array{hash: string, hashFunction: string}
     */
    public function forBrowser(): array
    {
        return [
            'hash' => $this->dataToBeSigned->digestBase64(),
            'hashFunction' => $this->algorithm->hashFunctionName(),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'version' => self::VERSION,
            'dataToBeSigned' => $this->dataToBeSigned->jsonSerialize(),
            'algorithm' => $this->algorithm->jsonSerialize(),
        ];
    }

    /**
     * @param array<mixed> $data
     */
    public static function fromArray(array $data): self
    {
        if (($data['version'] ?? null) !== self::VERSION) {
            throw new InvalidArgumentException('Unsupported Web eID signing session version');
        }
        $dataToBeSigned = $data['dataToBeSigned'] ?? null;
        $algorithm = $data['algorithm'] ?? null;
        if (!\is_array($dataToBeSigned) || !\is_array($algorithm)) {
            throw new InvalidArgumentException('A Web eID signing session needs both the data to be signed and the algorithm');
        }

        return new self(DataToBeSigned::fromArray($dataToBeSigned), CardAlgorithm::fromArray($algorithm));
    }

    public static function fromJson(string $json): self
    {
        $data = json_decode($json, true);
        if (!\is_array($data)) {
            throw new InvalidArgumentException('Web eID signing session JSON is not an object');
        }

        return self::fromArray($data);
    }
}
