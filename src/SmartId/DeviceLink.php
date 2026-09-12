<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Exception\InvalidArgumentException;

/**
 * The link that sends a person into the Smart-ID app, and the code that proves
 * the website built it.
 *
 * A device link is a URL the app opens: from a QR code the person scans, from a
 * tap in the same browser, or from another app. It carries an `authCode`, an
 * HMAC over everything that matters about the session, keyed with the session
 * secret. Without it the app refuses the link, which is what stops an attacker
 * who has seen a QR code from pointing the person at a session of their own.
 *
 * A QR link also carries how many seconds have passed since the session
 * started, and the app rejects a stale one. So a QR code has to be rebuilt
 * about once a second, each time with a fresh authentication code, which means
 * the browser has to ask the server for each new link. **The session secret
 * stays on the server**; only the finished link is ever sent to the browser.
 */
final readonly class DeviceLink
{
    public const VERSION = '1.0';

    public const TYPE_QR = 'QR';
    public const TYPE_WEB2APP = 'Web2App';
    public const TYPE_APP2APP = 'App2App';

    public const SESSION_AUTHENTICATION = 'auth';
    public const SESSION_SIGNATURE = 'sign';
    public const SESSION_CERTIFICATE_CHOICE = 'cert';

    /**
     * @param string      $linkType  one of the TYPE_ constants
     * @param string      $sessionType one of the SESSION_ constants
     * @param string      $payload   the rpChallenge or digest the session was started with, base64; empty for a certificate choice
     * @param string|null $brokeredRelyingPartyName set only when acting for another relying party
     */
    public function __construct(
        private string $scheme,
        private string $deviceLinkBase,
        private string $linkType,
        private string $sessionType,
        private string $sessionToken,
        private string $relyingPartyNameBase64,
        private string $interactionsEncoded,
        private string $payload,
        private string $language = 'eng',
        private ?string $initialCallbackUrl = null,
        private ?string $brokeredRelyingPartyName = null,
    ) {
        if (!\in_array($linkType, [self::TYPE_QR, self::TYPE_WEB2APP, self::TYPE_APP2APP], true)) {
            throw new InvalidArgumentException(\sprintf('Unknown device link type "%s"', $linkType));
        }
        if (!\in_array($sessionType, [self::SESSION_AUTHENTICATION, self::SESSION_SIGNATURE, self::SESSION_CERTIFICATE_CHOICE], true)) {
            throw new InvalidArgumentException(\sprintf('Unknown device link session type "%s"', $sessionType));
        }
        if ($deviceLinkBase === '' || $sessionToken === '') {
            throw new InvalidArgumentException('A device link needs the base URL and session token the service returned');
        }
        if (preg_match('/^[a-z]{3}$/', $language) !== 1) {
            throw new InvalidArgumentException('The language must be a three-letter lower-case code such as "est"');
        }
    }

    /**
     * The link without its authentication code. Not usable on its own; it is
     * the thing the code is computed over.
     *
     * @param int|null $elapsedSeconds seconds since the session started; QR links only
     */
    public function unprotectedUrl(?int $elapsedSeconds = null): string
    {
        if ($elapsedSeconds !== null && $this->linkType !== self::TYPE_QR) {
            throw new InvalidArgumentException('Only a QR link carries elapsed seconds');
        }
        if ($elapsedSeconds !== null && $elapsedSeconds < 0) {
            throw new InvalidArgumentException('Elapsed seconds cannot be negative');
        }

        // The order of these matters: the authentication code is computed over
        // this exact string, and the app rebuilds it the same way.
        $query = ['deviceLinkType' => $this->linkType];
        if ($elapsedSeconds !== null) {
            $query['elapsedSeconds'] = (string) $elapsedSeconds;
        }
        $query['sessionToken'] = $this->sessionToken;
        $query['sessionType'] = $this->sessionType;
        $query['version'] = self::VERSION;
        $query['lang'] = $this->language;

        $separator = str_contains($this->deviceLinkBase, '?') ? '&' : '?';

        return $this->deviceLinkBase . $separator . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * The finished link, for a QR code or a tap.
     *
     * @param string   $sessionSecret  from the session response; never send this to a browser
     * @param int|null $elapsedSeconds seconds since the session started; QR links only
     */
    public function url(string $sessionSecret, ?int $elapsedSeconds = null): string
    {
        $unprotected = $this->unprotectedUrl($elapsedSeconds);

        return $unprotected . '&authCode=' . $this->authenticationCode($sessionSecret, $unprotected);
    }

    /**
     * The HMAC that proves this link belongs to this session.
     *
     * @param string $unprotectedUrl the output of {@see unprotectedUrl()}
     */
    public function authenticationCode(string $sessionSecret, string $unprotectedUrl): string
    {
        $key = base64_decode($sessionSecret, true);
        if ($key === false || $key === '') {
            throw new InvalidArgumentException('The session secret is not base64');
        }

        $hmac = hash_hmac('sha256', $this->payload($unprotectedUrl), $key, true);

        return self::base64Url($hmac);
    }

    /**
     * Everything the code covers, joined with pipes.
     */
    public function payload(string $unprotectedUrl): string
    {
        return implode('|', [
            $this->scheme,
            $this->signatureProtocol(),
            $this->payload,
            $this->relyingPartyNameBase64,
            $this->brokeredRelyingPartyName === null ? '' : base64_encode($this->brokeredRelyingPartyName),
            $this->interactionsEncoded,
            $this->initialCallbackUrl ?? '',
            $unprotectedUrl,
        ]);
    }

    private function signatureProtocol(): string
    {
        return match ($this->sessionType) {
            self::SESSION_AUTHENTICATION => SmartIdClient::PROTOCOL_ACSP_V2,
            self::SESSION_SIGNATURE => SmartIdClient::PROTOCOL_RAW_DIGEST,
            default => '',
        };
    }

    /**
     * Base64 without padding and with URL-safe characters, which is what the
     * protocol uses throughout.
     */
    public static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
