<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support\WebEid;

use Allkiri\Crypto\KeyPair;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Tests\Support\Pki\TestPki;

/**
 * Builds a Web eID authentication token the way a card and the browser
 * extension would.
 *
 * The signed value is `hash(origin) || hash(challenge)`, with the hash matching
 * the signature algorithm, and the whole thing is signed with the card's
 * authentication key. Producing it here rather than replaying a captured token
 * means the tests exercise the real construction: change the origin or the
 * challenge and the signature stops verifying, which is the property the format
 * exists to provide.
 */
final class TestAuthToken
{
    public const FORMAT = 'web-eid:1.0';

    private function __construct() {}

    /**
     * @param string|null $signOrigin    sign a different origin than the one claimed, for negative tests
     * @param string|null $signChallenge sign a different challenge, likewise
     */
    public static function create(
        string $origin,
        string $challenge,
        ?KeyPair $keyPair = null,
        SignatureAlgorithm $algorithm = SignatureAlgorithm::ES384,
        ?string $signOrigin = null,
        ?string $signChallenge = null,
        ?string $format = null,
    ): string {
        $keyPair ??= TestPki::cardAuth();

        $hash = $algorithm->hash();
        $signed = $hash->digest($signOrigin ?? $origin) . $hash->digest($signChallenge ?? $challenge);

        return self::encode([
            'unverifiedCertificate' => $keyPair->certificate->base64(),
            'algorithm' => $algorithm->value,
            'signature' => base64_encode($keyPair->privateKey->sign($algorithm, $signed)),
            'format' => $format ?? self::FORMAT,
            'appVersion' => 'https://web-eid.eu/web-eid-app/releases/v2.7.0',
        ]);
    }

    /**
     * A token whose signature is valid in shape but not in fact.
     */
    public static function withCorruptSignature(string $origin, string $challenge, ?KeyPair $keyPair = null): string
    {
        $token = json_decode(self::create($origin, $challenge, $keyPair), true);
        \assert(\is_array($token));
        $encoded = $token['signature'] ?? null;
        \assert(\is_string($encoded));
        $signature = base64_decode($encoded, true);
        \assert(\is_string($signature));
        $signature[\strlen($signature) - 1] = \chr(\ord($signature[\strlen($signature) - 1]) ^ 0xFF);
        $token['signature'] = base64_encode($signature);

        return self::encode($token);
    }

    /**
     * A token with one field removed or replaced.
     */
    public static function modified(string $origin, string $challenge, string $field, mixed $value): string
    {
        $token = json_decode(self::create($origin, $challenge), true);
        \assert(\is_array($token));
        if ($value === null) {
            unset($token[$field]);
        } else {
            $token[$field] = $value;
        }

        return self::encode($token);
    }

    /**
     * @param array<mixed> $token
     */
    private static function encode(array $token): string
    {
        $json = json_encode($token, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        // The validator refuses anything under 100 characters, which a token
        // with a short certificate could otherwise fall below.
        \assert(\strlen($json) >= 100);

        return $json;
    }
}
