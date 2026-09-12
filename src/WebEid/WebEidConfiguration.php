<?php

declare(strict_types=1);

namespace Allkiri\WebEid;

use Allkiri\Exception\InvalidArgumentException;

/**
 * What a website tells the library about itself.
 *
 * Unlike Mobile-ID and Smart-ID there is no relying-party contract and no
 * service to be registered with: the card talks to the browser, and the only
 * thing the server has to get right is its own origin.
 */
final readonly class WebEidConfiguration
{
    /**
     * The Mobile-ID certificate policy. Disallowed by default so that a
     * Mobile-ID certificate cannot be presented through Web eID: a site that
     * asked for a card should be answered by a card, and the two means have
     * different assurance and different revocation behaviour.
     */
    public const MOBILE_ID_POLICY_PREFIX = '1.3.6.1.4.1.10015.1.3';

    /**
     * @param list<string> $disallowedCertificatePolicies certificate policy OIDs to refuse
     */
    public function __construct(
        public WebEidOrigin $origin,
        public int $challengeTtlSeconds = 300,
        public array $disallowedCertificatePolicies = [self::MOBILE_ID_POLICY_PREFIX],
        public bool $checkRevocation = true,
    ) {
        if ($challengeTtlSeconds < 1) {
            throw new InvalidArgumentException('The challenge lifetime must be at least one second');
        }
        // Long enough to insert a card and find a PIN, short enough that a
        // captured challenge is of little use.
        if ($challengeTtlSeconds > 3600) {
            throw new InvalidArgumentException('The challenge lifetime must not exceed an hour');
        }
    }

    public static function forOrigin(string $origin): self
    {
        return new self(WebEidOrigin::parse($origin));
    }

    public function withChallengeTtl(int $seconds): self
    {
        return new self($this->origin, $seconds, $this->disallowedCertificatePolicies, $this->checkRevocation);
    }

    /**
     * @param list<string> $policies
     */
    public function withDisallowedCertificatePolicies(array $policies): self
    {
        return new self($this->origin, $this->challengeTtlSeconds, $policies, $this->checkRevocation);
    }

    /**
     * Turn off the revocation check.
     *
     * Only for a test environment whose responder cannot be reached. A
     * certificate that has been revoked because the card was lost is exactly
     * the one an attacker would present.
     */
    public function withoutRevocationCheck(): self
    {
        return new self($this->origin, $this->challengeTtlSeconds, $this->disallowedCertificatePolicies, false);
    }
}
