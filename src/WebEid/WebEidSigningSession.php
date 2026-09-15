<?php

declare(strict_types=1);

namespace Allkiri\WebEid;

use Allkiri\Signing\DataToBeSigned;
use Allkiri\StoredData;

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
    public static function fromArray(#[\SensitiveParameter] array $data): self
    {
        return StoredData::restore($data, 'Web eID signing session', [self::VERSION], static fn(#[\SensitiveParameter] StoredData $stored): self => new self(
            DataToBeSigned::fromArray($stored->object('dataToBeSigned')),
            CardAlgorithm::fromArray($stored->object('algorithm')),
        ));
    }

    public static function fromJson(#[\SensitiveParameter] string $json): self
    {
        return self::fromArray(StoredData::decode($json, 'Web eID signing session'));
    }
}
