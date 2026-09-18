<?php

declare(strict_types=1);

namespace Allkiri\WebEid;

use Allkiri\Exception\InvalidArgumentException;

/**
 * The website's origin, in the exact form the card signs.
 *
 * This is the load-bearing value of the whole protocol. An authentication
 * signs `hash(origin) || hash(challenge)` and the token carries neither, so the
 * server has to supply both from its own knowledge. Get the origin wrong and
 * either nothing verifies, or — worse — it verifies for a site that is not
 * yours, which is precisely the relay attack the format exists to prevent.
 *
 * The form is the ASCII serialisation of an origin: `https://host[:port]`, no
 * trailing slash, no path, and internationalised names in Punycode. It is what
 * a browser reports as `location.origin`, so the safest way to configure it is
 * to copy that.
 */
final readonly class WebEidOrigin implements \Stringable
{
    private function __construct(public string $value) {}

    /**
     * @param string $origin `https://example.ee`, `https://example.ee:8443`, or a
     *                       URL to take the origin of
     */
    public static function parse(string $origin): self
    {
        $trimmed = trim($origin);
        if ($trimmed === '') {
            throw new InvalidArgumentException('The site origin must not be empty');
        }

        $parts = parse_url($trimmed);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            throw new InvalidArgumentException(\sprintf('"%s" is not an origin such as https://example.ee', $origin));
        }
        // Only HTTPS: the extension refuses to work on an insecure origin, and a
        // signature over an http origin would be worthless anyway.
        if (strtolower($parts['scheme']) !== 'https') {
            throw new InvalidArgumentException(\sprintf('The site origin must use https, got "%s"', $parts['scheme']));
        }
        foreach (['user', 'pass', 'query', 'fragment'] as $forbidden) {
            if (isset($parts[$forbidden])) {
                throw new InvalidArgumentException('The site origin must be only the scheme, host and optional port');
            }
        }
        if (isset($parts['path']) && $parts['path'] !== '' && $parts['path'] !== '/') {
            throw new InvalidArgumentException(\sprintf('The site origin must carry no path, got "%s"', $parts['path']));
        }

        $host = self::asciiHost($parts['host']);
        $port = $parts['port'] ?? null;
        if ($port !== null && ($port < 1 || $port > 65535)) {
            throw new InvalidArgumentException('The site origin port must be between 1 and 65535');
        }
        // 443 is the default for https and a browser leaves it out, so including
        // it here would produce an origin that never matches.
        $serialised = 'https://' . $host . ($port === null || $port === 443 ? '' : ':' . $port);

        return new self($serialised);
    }

    /**
     * Internationalised names are signed in Punycode, so `https://päike.ee`
     * becomes `https://xn--pike-loa.ee`.
     */
    private static function asciiHost(string $host): string
    {
        $lower = mb_strtolower($host, 'UTF-8');
        if (preg_match('/^[a-z0-9.\-]+\z/', $lower) === 1) {
            return $lower;
        }
        if (!\function_exists('idn_to_ascii')) {
            throw new InvalidArgumentException(\sprintf(
                'The site origin host "%s" is not ASCII and the intl extension is not available to convert it; configure the Punycode form instead',
                $host,
            ));
        }
        $ascii = idn_to_ascii($lower, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        if (!\is_string($ascii) || $ascii === '') {
            throw new InvalidArgumentException(\sprintf('The site origin host "%s" cannot be converted to Punycode', $host));
        }

        return $ascii;
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
