<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Crypto\NonceGenerator;
use Allkiri\Crypto\RandomNonceGenerator;
use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Http\HttpRequest;

/**
 * What the Smart-ID app brings back when a Web2App or App2App flow returns to
 * you: the callback URL the session was started with, and the parameters the
 * app added to it.
 *
 * Build one from the query of the request the app opened, and hand it to the
 * authenticator's or the signer's `poll()` or `complete()`. They check it with
 * {@see SmartIdSession::verifyCallback()} before believing the answer.
 *
 * Two things remain yours: the session you check it against must be the one
 * this browser started, found through the browser's own session rather than
 * through anything in the URL, and it must be forgotten once used, so the same
 * callback is never accepted twice.
 */
final readonly class SmartIdCallback
{
    /** The random parameter {@see initialUrl()} adds, as SK's own clients name it. */
    public const VALUE = 'value';

    public const SESSION_SECRET_DIGEST = 'sessionSecretDigest';

    public const USER_CHALLENGE_VERIFIER = 'userChallengeVerifier';

    /** How many random bytes the value carries: 43 characters once encoded. */
    private const VALUE_BYTES = 32;

    /**
     * @param array<string, string> $parameters every query parameter the callback arrived with
     */
    public function __construct(public array $parameters) {}

    /**
     * From an already parsed query, such as `$_GET`. Anything that is not a
     * single string value, as `a[]=1` would make, is left out.
     *
     * @param array<mixed> $query
     */
    public static function fromQuery(array $query): self
    {
        $parameters = [];
        foreach ($query as $name => $value) {
            if (\is_string($value)) {
                $parameters[(string) $name] = $value;
            }
        }

        return new self($parameters);
    }

    /**
     * From the whole URL the app opened.
     */
    public static function fromUrl(string $url): self
    {
        return self::fromQuery(self::query($url));
    }

    /**
     * A callback URL for a new session: `$baseUrl` with a random `value` added,
     * so that no two sessions share one and nobody can predict the next.
     *
     * Keep the result with the session; it is also
     * `SmartIdSession::$initialCallbackUrl`, which is what the callback is
     * checked against.
     *
     * @param string $baseUrl where the app sends the person back: https://, or http:// to this machine only
     */
    public static function initialUrl(string $baseUrl, NonceGenerator $nonces = new RandomNonceGenerator()): string
    {
        HttpRequest::requireHttps($baseUrl, 'The callback URL');
        if (str_contains($baseUrl, '#')) {
            throw new InvalidArgumentException('The callback URL must not have a fragment: the app would drop it');
        }
        if (\array_key_exists(self::VALUE, self::query($baseUrl))) {
            throw new InvalidArgumentException(\sprintf('The callback URL already has a "%s" parameter; it is added here', self::VALUE));
        }

        $url = $baseUrl
            . (str_contains($baseUrl, '?') ? '&' : '?')
            . self::VALUE . '=' . DeviceLink::base64Url($nonces->generate(self::VALUE_BYTES));
        SmartIdSession::requireUsableCallbackUrl($url);

        return $url;
    }

    /**
     * The SHA-256 of the session secret the app returned, to prove it knew it.
     */
    public function sessionSecretDigest(): ?string
    {
        return $this->parameters[self::SESSION_SECRET_DIGEST] ?? null;
    }

    /**
     * The value whose SHA-256 the app put in an authentication's signed payload.
     * Signing callbacks carry none.
     */
    public function userChallengeVerifier(): ?string
    {
        return $this->parameters[self::USER_CHALLENGE_VERIFIER] ?? null;
    }

    /**
     * The query of a URL, decoded as PHP decodes `$_GET`.
     *
     * @return array<mixed>
     */
    private static function query(string $url): array
    {
        $query = parse_url($url, PHP_URL_QUERY);
        if (!\is_string($query) || $query === '') {
            return [];
        }
        parse_str($query, $parsed);

        return $parsed;
    }
}
