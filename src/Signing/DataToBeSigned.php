<?php

declare(strict_types=1);

namespace Allkiri\Signing;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\StoredData;

/**
 * Everything a signing session needs to survive between two HTTP requests.
 *
 * A remote signer (Web eID, Mobile-ID, Smart-ID) is asked to sign
 * {@see digest()}; the application stores this object meanwhile and hands it
 * back to {@see SigningService::finalize()} with the value it received.
 *
 * It is JSON-serialisable on purpose: a session store, a database column and
 * a queue message all work, and nothing here is secret.
 */
final readonly class DataToBeSigned implements \JsonSerializable
{
    public const VERSION = 1;

    public function __construct(
        public string $signatureId,
        public string $signatureFileName,
        public SignatureAlgorithm $algorithm,
        public string $digest,
        public string $signedInfoCanonical,
        public string $signatureXml,
        public Certificate $signerCertificate,
        public string $containerFingerprint,
        public SignatureLevel $level,
        public \DateTimeImmutable $createdAt,
    ) {}

    public function digestAlgorithm(): HashAlgorithm
    {
        return $this->algorithm->hash();
    }

    public function digestBase64(): string
    {
        return base64_encode($this->digest);
    }

    public function digestHex(): string
    {
        return bin2hex($this->digest);
    }

    /**
     * The hash name Mobile-ID and Smart-ID expect ("SHA256").
     */
    public function hashName(): string
    {
        return $this->algorithm->hash()->name();
    }

    /**
     * @return array<string, string|int>
     */
    public function jsonSerialize(): array
    {
        return [
            'version' => self::VERSION,
            'signatureId' => $this->signatureId,
            'signatureFileName' => $this->signatureFileName,
            'algorithm' => $this->algorithm->value,
            'digest' => base64_encode($this->digest),
            'signedInfoCanonical' => base64_encode($this->signedInfoCanonical),
            'signatureXml' => base64_encode($this->signatureXml),
            'signerCertificate' => $this->signerCertificate->base64(),
            'containerFingerprint' => $this->containerFingerprint,
            'level' => $this->level->value,
            'createdAt' => $this->createdAt->format(DATE_ATOM),
        ];
    }

    /**
     * @param array<mixed> $data the output of {@see jsonSerialize()}
     */
    public static function fromArray(#[\SensitiveParameter] array $data): self
    {
        return StoredData::restore($data, 'DataToBeSigned', [self::VERSION], static fn(#[\SensitiveParameter] StoredData $stored): self => new self(
            $stored->string('signatureId'),
            $stored->string('signatureFileName'),
            $stored->enum('algorithm', SignatureAlgorithm::class),
            $stored->base64('digest'),
            $stored->base64('signedInfoCanonical'),
            $stored->base64('signatureXml'),
            $stored->certificate('signerCertificate'),
            $stored->string('containerFingerprint'),
            $stored->enum('level', SignatureLevel::class),
            $stored->date('createdAt'),
        ));
    }

    /**
     * @throws \Allkiri\Exception\SessionDataException when what was stored cannot be read back
     */
    public static function fromJson(#[\SensitiveParameter] string $json): self
    {
        return self::fromArray(StoredData::decode($json, 'DataToBeSigned'));
    }
}
