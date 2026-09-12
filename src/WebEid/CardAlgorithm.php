<?php

declare(strict_types=1);

namespace Allkiri\WebEid;

use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\KeyType;
use Allkiri\Crypto\SignatureAlgorithm;

/**
 * One signature algorithm as the browser describes it.
 *
 * `getSigningCertificate()` reports what the card can do as a list of these
 * triples, and `sign()` reports which one it used. The browser splits the
 * algorithm into three fields where XML-DSig names it in one, so this is where
 * the two vocabularies meet.
 *
 * Note that `sign()` is given only the hash function, not the padding: the card
 * chooses that and reports it afterwards. So the padding has to be worked out
 * in advance from what the card said it supports, and the answer checked
 * against it.
 */
final readonly class CardAlgorithm implements \JsonSerializable
{
    public const CRYPTO_ECC = 'ECC';
    public const CRYPTO_RSA = 'RSA';

    public const PADDING_NONE = 'NONE';
    public const PADDING_PKCS15 = 'PKCS1.5';
    public const PADDING_PSS = 'PSS';

    public function __construct(
        public string $cryptoAlgorithm,
        public string $hashFunction,
        public string $paddingScheme,
    ) {}

    /**
     * Read one entry of `supportedSignatureAlgorithms`.
     *
     * @param array<mixed> $data
     */
    public static function fromArray(array $data): self
    {
        foreach (['cryptoAlgorithm', 'hashFunction', 'paddingScheme'] as $key) {
            if (!\is_string($data[$key] ?? null) || $data[$key] === '') {
                throw new WebEidException(\sprintf('A supported signature algorithm is missing "%s"', $key));
            }
        }

        /** @var array{cryptoAlgorithm: string, hashFunction: string, paddingScheme: string} $data */
        return new self($data['cryptoAlgorithm'], $data['hashFunction'], $data['paddingScheme']);
    }

    /**
     * Read a whole `supportedSignatureAlgorithms` list.
     *
     * @param array<mixed> $entries
     *
     * @return list<self>
     */
    public static function listFromArray(array $entries): array
    {
        $algorithms = [];
        foreach ($entries as $entry) {
            if (!\is_array($entry)) {
                throw new WebEidException('A supported signature algorithm is not an object');
            }
            $algorithms[] = self::fromArray($entry);
        }

        return $algorithms;
    }

    /**
     * The XML-DSig signature method this triple corresponds to, or null when
     * there is none in the profile allkiri produces.
     *
     * SHA-224 and the SHA-3 family are reported by some cards and have no
     * signature method here, so they come back null rather than guessed at.
     */
    public function signatureAlgorithm(): ?SignatureAlgorithm
    {
        $bits = match (strtoupper($this->hashFunction)) {
            'SHA-256', 'SHA256' => '256',
            'SHA-384', 'SHA384' => '384',
            'SHA-512', 'SHA512' => '512',
            default => null,
        };
        if ($bits === null) {
            return null;
        }

        $prefix = match (true) {
            strtoupper($this->cryptoAlgorithm) === self::CRYPTO_ECC => 'ES',
            $this->paddingScheme === self::PADDING_PSS => 'PS',
            $this->paddingScheme === self::PADDING_PKCS15 => 'RS',
            default => null,
        };

        return $prefix === null ? null : SignatureAlgorithm::tryFrom($prefix . $bits);
    }

    /**
     * The hash function name to pass to `sign()`.
     */
    public function hashFunctionName(): string
    {
        return $this->hashFunction;
    }

    /**
     * How the browser would name a signature method, for comparing what a card
     * reported with what was prepared.
     */
    public static function forSignatureAlgorithm(SignatureAlgorithm $algorithm): self
    {
        $hash = $algorithm->hash()->name(true);
        if ($algorithm->keyType() === KeyType::EC) {
            return new self(self::CRYPTO_ECC, $hash, self::PADDING_NONE);
        }

        return new self(self::CRYPTO_RSA, $hash, $algorithm->isPss() ? self::PADDING_PSS : self::PADDING_PKCS15);
    }

    public function hashAlgorithm(): ?HashAlgorithm
    {
        return $this->signatureAlgorithm()?->hash();
    }

    public function equals(self $other): bool
    {
        return strtoupper($this->cryptoAlgorithm) === strtoupper($other->cryptoAlgorithm)
            && strtoupper($this->hashFunction) === strtoupper($other->hashFunction)
            && $this->paddingScheme === $other->paddingScheme;
    }

    public function __toString(): string
    {
        return \sprintf('%s/%s/%s', $this->cryptoAlgorithm, $this->hashFunction, $this->paddingScheme);
    }

    /**
     * @return array<string, string>
     */
    public function jsonSerialize(): array
    {
        return [
            'cryptoAlgorithm' => $this->cryptoAlgorithm,
            'hashFunction' => $this->hashFunction,
            'paddingScheme' => $this->paddingScheme,
        ];
    }
}
