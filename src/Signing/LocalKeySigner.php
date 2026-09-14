<?php

declare(strict_types=1);

namespace Allkiri\Signing;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\KeyPair;
use Allkiri\Crypto\PrivateKey;

/**
 * Signs with a key this process holds: an organisation's e-seal, or a test key.
 */
final class LocalKeySigner implements Signer
{
    public function __construct(
        private readonly PrivateKey $privateKey,
        private readonly Certificate $certificate,
    ) {}

    public static function fromKeyPair(KeyPair $keyPair): self
    {
        return new self($keyPair->privateKey, $keyPair->certificate);
    }

    public static function fromPkcs12(#[\SensitiveParameter] string $pkcs12, #[\SensitiveParameter] string $password): self
    {
        return self::fromKeyPair(PrivateKey::fromPkcs12($pkcs12, $password));
    }

    public function certificate(): Certificate
    {
        return $this->certificate;
    }

    public function sign(DataToBeSigned $dataToBeSigned): string
    {
        return $this->privateKey->sign($dataToBeSigned->algorithm, $dataToBeSigned->signedInfoCanonical);
    }
}
