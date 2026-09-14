<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Http\HttpRequest;

/**
 * Who we are to Smart-ID, and what we ask of it.
 *
 * The scheme name is not decoration: it goes into the signed payload of an
 * authentication and into the authentication code of a device link, so a demo
 * configuration pointed at production (or the reverse) fails verification
 * rather than quietly working.
 */
final readonly class SmartIdConfiguration
{
    public const DEMO_URL = 'https://sid.demo.sk.ee/smart-id-rp/v3';
    public const PRODUCTION_URL = 'https://rp-api.smart-id.com/v3';

    public const DEMO_RELYING_PARTY_UUID = '00000000-0000-4000-8000-000000000000';
    public const DEMO_RELYING_PARTY_NAME = 'DEMO';

    public const SCHEME_DEMO = 'smart-id-demo';
    public const SCHEME_PRODUCTION = 'smart-id';

    /** Above this the service uses its own maximum instead. */
    public const MAX_POLL_TIMEOUT_MS = 120_000;

    public const HTTP_TIMEOUT_MARGIN_SECONDS = 5;

    /**
     * @param string        $scheme               `smart-id` or `smart-id-demo`; must match the URL
     * @param HashAlgorithm $signingHashAlgorithm the digest the app signs when signing
     * @param bool          $checkRevocation      whether sign-in asks the certificate's OCSP responder
     */
    public function __construct(
        public string $url,
        #[\SensitiveParameter]
        public string $relyingPartyUuid,
        public string $relyingPartyName,
        public string $scheme,
        public CertificateLevel $certificateLevel = CertificateLevel::Qualified,
        public HashAlgorithm $signingHashAlgorithm = HashAlgorithm::SHA256,
        public int $pollTimeoutMs = 10_000,
        public int $sessionTimeoutSeconds = 120,
        public bool $shareDeviceIpAddress = false,
        public bool $checkRevocation = true,
    ) {
        // The relying-party identifier and the people being asked for go to
        // this URL.
        HttpRequest::requireHttps($url, 'The Smart-ID service URL');
        if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $relyingPartyUuid) !== 1) {
            throw new InvalidArgumentException('The relying party identifier must be a lower-case UUID in 8-4-4-4-12 form');
        }
        if ($relyingPartyName === '') {
            throw new InvalidArgumentException('The relying party name must not be empty');
        }
        // The name is signed as base64, and SK limits it to 32 characters.
        if (mb_strlen($relyingPartyName, 'UTF-8') > 32) {
            throw new InvalidArgumentException('The relying party name must not exceed 32 characters');
        }
        if ($scheme !== self::SCHEME_DEMO && $scheme !== self::SCHEME_PRODUCTION) {
            throw new InvalidArgumentException(\sprintf('The scheme must be "%s" or "%s"', self::SCHEME_PRODUCTION, self::SCHEME_DEMO));
        }
        if ($pollTimeoutMs < 1_000 || $pollTimeoutMs > self::MAX_POLL_TIMEOUT_MS) {
            throw new InvalidArgumentException(\sprintf('The poll timeout must be between 1000 and %d milliseconds', self::MAX_POLL_TIMEOUT_MS));
        }
        if ($sessionTimeoutSeconds < 1) {
            throw new InvalidArgumentException('The session timeout must be at least one second');
        }
    }

    /**
     * The public demo service. Only the published test accounts answer on it.
     */
    public static function demo(): self
    {
        return new self(
            self::DEMO_URL,
            self::DEMO_RELYING_PARTY_UUID,
            self::DEMO_RELYING_PARTY_NAME,
            self::SCHEME_DEMO,
        );
    }

    public static function production(#[\SensitiveParameter] string $relyingPartyUuid, string $relyingPartyName): self
    {
        return new self(self::PRODUCTION_URL, $relyingPartyUuid, $relyingPartyName, self::SCHEME_PRODUCTION);
    }

    public function isDemo(): bool
    {
        return $this->scheme === self::SCHEME_DEMO;
    }

    /**
     * The shortest HTTP timeout that will not cut a long poll short.
     */
    public function httpTimeoutSeconds(): int
    {
        return (int) ceil($this->pollTimeoutMs / 1000) + self::HTTP_TIMEOUT_MARGIN_SECONDS;
    }

    /**
     * The relying party name as the signed payload carries it.
     */
    public function relyingPartyNameBase64(): string
    {
        return base64_encode($this->relyingPartyName);
    }

    public function withCertificateLevel(CertificateLevel $level): self
    {
        return new self($this->url, $this->relyingPartyUuid, $this->relyingPartyName, $this->scheme, $level, $this->signingHashAlgorithm, $this->pollTimeoutMs, $this->sessionTimeoutSeconds, $this->shareDeviceIpAddress, $this->checkRevocation);
    }

    public function withSigningHashAlgorithm(HashAlgorithm $algorithm): self
    {
        return new self($this->url, $this->relyingPartyUuid, $this->relyingPartyName, $this->scheme, $this->certificateLevel, $algorithm, $this->pollTimeoutMs, $this->sessionTimeoutSeconds, $this->shareDeviceIpAddress, $this->checkRevocation);
    }

    public function withTimeouts(int $pollTimeoutMs, int $sessionTimeoutSeconds): self
    {
        return new self($this->url, $this->relyingPartyUuid, $this->relyingPartyName, $this->scheme, $this->certificateLevel, $this->signingHashAlgorithm, $pollTimeoutMs, $sessionTimeoutSeconds, $this->shareDeviceIpAddress, $this->checkRevocation);
    }

    /**
     * Ask the service for the IP address the Smart-ID app connected from.
     *
     * Needs to be enabled for the relying party; it is reported in the session
     * status and is useful for fraud monitoring.
     */
    public function withDeviceIpAddress(bool $share = true): self
    {
        return new self($this->url, $this->relyingPartyUuid, $this->relyingPartyName, $this->scheme, $this->certificateLevel, $this->signingHashAlgorithm, $this->pollTimeoutMs, $this->sessionTimeoutSeconds, $share, $this->checkRevocation);
    }

    /**
     * Turn off the revocation check at sign-in.
     *
     * Only for a test environment whose responder cannot be reached. SK asks
     * relying parties to check that a Smart-ID authentication certificate has
     * not been revoked, and a revoked certificate is exactly the one somebody
     * who should no longer sign in would present.
     */
    public function withoutRevocationCheck(): self
    {
        return new self($this->url, $this->relyingPartyUuid, $this->relyingPartyName, $this->scheme, $this->certificateLevel, $this->signingHashAlgorithm, $this->pollTimeoutMs, $this->sessionTimeoutSeconds, $this->shareDeviceIpAddress, false);
    }
}
