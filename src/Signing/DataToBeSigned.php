<?php

declare(strict_types=1);

namespace Allkiri\Signing;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Exception\InvalidArgumentException;

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
    public static function fromArray(array $data): self
    {
        $version = $data['version'] ?? null;
        if ($version !== self::VERSION) {
            throw new InvalidArgumentException(\sprintf('Unsupported DataToBeSigned version %s', \is_scalar($version) ? (string) $version : 'none'));
        }

        return new self(
            self::string($data, 'signatureId'),
            self::string($data, 'signatureFileName'),
            SignatureAlgorithm::from(self::string($data, 'algorithm')),
            self::base64($data, 'digest'),
            self::base64($data, 'signedInfoCanonical'),
            self::base64($data, 'signatureXml'),
            Certificate::fromBase64(self::string($data, 'signerCertificate')),
            self::string($data, 'containerFingerprint'),
            SignatureLevel::from(self::string($data, 'level')),
            new \DateTimeImmutable(self::string($data, 'createdAt')),
        );
    }

    public static function fromJson(string $json): self
    {
        $data = json_decode($json, true);
        if (!\is_array($data)) {
            throw new InvalidArgumentException('DataToBeSigned JSON is not an object');
        }

        return self::fromArray($data);
    }

    /**
     * @param array<mixed> $data
     */
    private static function string(array $data, string $key): string
    {
        $value = $data[$key] ?? null;
        if (!\is_string($value) || $value === '') {
            throw new InvalidArgumentException(\sprintf('DataToBeSigned is missing "%s"', $key));
        }

        return $value;
    }

    /**
     * @param array<mixed> $data
     */
    private static function base64(array $data, string $key): string
    {
        $decoded = base64_decode(self::string($data, $key), true);
        if ($decoded === false || $decoded === '') {
            throw new InvalidArgumentException(\sprintf('DataToBeSigned field "%s" is not base64', $key));
        }

        return $decoded;
    }
}
