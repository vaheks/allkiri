<?php

declare(strict_types=1);

namespace Allkiri\WebEid;

use Allkiri\Auth\AuthenticatedIdentity;
use Allkiri\Clock\SystemClock;
use Allkiri\Crypto\Asn1\Asn1Exception;
use Allkiri\Crypto\Asn1\NestingGuard;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\CertificateException;
use Allkiri\Crypto\EcdsaSignature;
use Allkiri\Crypto\NonceGenerator;
use Allkiri\Crypto\Ocsp\CertificateRevokedException;
use Allkiri\Crypto\Ocsp\OcspClient;
use Allkiri\Crypto\Ocsp\OcspException;
use Allkiri\Crypto\RandomNonceGenerator;
use Allkiri\Trust\ChainBuilder;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustException;
use Allkiri\Trust\TrustStore;
use GuzzleHttp\Psr7\Uri;
use phpseclib3\File\X509;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenValidator;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenValidatorBuilder;

/**
 * Signing in with an ID card, through Web eID.
 *
 * Two steps, but unlike the phone-based means the waiting happens in the
 * browser rather than on the server: `challenge()` gives the page something for
 * the card to sign, and `validate()` checks what comes back. There is nothing
 * to poll.
 *
 * ```php
 * // GET /auth/challenge
 * $challenge = $authenticator->challenge();
 * $_SESSION['web-eid'] = json_encode($challenge);
 * echo json_encode(['nonce' => $challenge->nonce]);
 *
 * // POST /auth/login, with the token the browser produced
 * $identity = $authenticator->validate($tokenJson, WebEidChallenge::fromJson($_SESSION['web-eid']));
 * unset($_SESSION['web-eid']);
 * ```
 *
 * The challenge must be stored against the browser session that asked for it
 * and used once. The token carries neither the challenge nor the origin, so
 * looking the challenge up by session is the only way, and that is what ties
 * the answer to the browser that started it.
 *
 * ## What checks what
 *
 * The token itself — its format, the signature over origin and challenge, the
 * certificate's key usage and policies — is validated by
 * `web-eid/web-eid-authtoken-validation-php`, the implementation RIA maintains
 * and has had analysed. Trust and revocation are done here instead, with the
 * same trust store, chain builder and OCSP client every other part of allkiri
 * uses, so a card is judged the same way a Mobile-ID or Smart-ID certificate
 * is and its revocation check has the same properties.
 */
final class WebEidAuthenticator
{
    /** 32 bytes of entropy, which base64 renders as the 44 characters the specification requires. */
    private const CHALLENGE_BYTES = 32;

    public function __construct(
        private readonly WebEidConfiguration $configuration,
        private readonly TrustStore $trustStore,
        private readonly ?OcspClient $ocspClient = null,
        private readonly ?ChainBuilder $chainBuilder = null,
        private readonly NonceGenerator $nonceGenerator = new RandomNonceGenerator(),
        private readonly ClockInterface $clock = new SystemClock(),
        private readonly ?LoggerInterface $logger = null,
    ) {}

    /**
     * Something for the card to sign. Store it, and send only the nonce to the
     * browser.
     */
    public function challenge(): WebEidChallenge
    {
        $now = $this->now();

        return new WebEidChallenge(
            base64_encode($this->nonceGenerator->generate(self::CHALLENGE_BYTES)),
            $now,
            $now->add(new \DateInterval('PT' . $this->configuration->challengeTtlSeconds . 'S')),
        );
    }

    /**
     * Check the token the browser produced and return who it proves was there.
     *
     * @param string $authToken the JSON the browser's `authenticate()` returned
     *
     * @throws WebEidException when the token does not hold up
     */
    public function validate(string $authToken, WebEidChallenge $challenge): AuthenticatedIdentity
    {
        $now = $this->now();
        // Freshness is the website's own business: the token has no timestamp,
        // and the specification says to judge it by when the challenge was
        // issued rather than by anything the card claims.
        if ($challenge->isExpiredAt($now)) {
            throw new WebEidException(\sprintf(
                'The Web eID challenge expired at %s; ask for a new one',
                $challenge->expiresAt->format(DATE_ATOM),
            ));
        }

        self::refuseDeeplyNestedCertificate($authToken);
        $validator = $this->validator();
        try {
            $parsed = $validator->parse(self::withDerSignature($authToken));
            $validator->validate($parsed, $challenge->nonce);
        } catch (\Throwable $exception) {
            // Deliberately broad. This is the boundary where a string from the
            // network is interpreted, and the validator does not always reach
            // its own exceptions: a token missing "algorithm" or "signature"
            // gets as far as a TypeError, which an application catching the
            // library's exceptions would never see. Everything thrown in here
            // means one thing, that the token was refused, and a refused login
            // must not surface as a server error.
            throw new WebEidException('The Web eID token was refused: ' . $exception->getMessage(), 0, $exception);
        }

        // Read the certificate from the token's own bytes rather than
        // re-encoding what the validator parsed: everything downstream verifies
        // against the original DER, and a re-encoding is not guaranteed to be
        // the same bytes.
        $certificate = $this->toCertificate($parsed->getUnverifiedCertificate());
        $this->verifyTrust($certificate, $now);

        $identity = AuthenticatedIdentity::fromCertificate($certificate);
        $this->logger?->info('Web eID authenticated {identity}', ['identity' => $identity->semanticsIdentifier()]);

        return $identity;
    }

    // --- trust and revocation ----------------------------------------------

    private function verifyTrust(Certificate $certificate, \DateTimeImmutable $now): void
    {
        if (!$certificate->isValidAt($now)) {
            throw new WebEidException('The card certificate is not valid at this moment');
        }

        $chainBuilder = $this->chainBuilder ?? new ChainBuilder($this->trustStore);
        try {
            $chain = $chainBuilder->build($certificate, [], $now, [ServiceType::CaQc, ServiceType::CaPkc]);
        } catch (TrustException $exception) {
            throw new WebEidException('The card certificate does not chain to a trusted authority: ' . $exception->getMessage(), 0, $exception);
        }

        if (!$this->configuration->checkRevocation) {
            $this->logger?->warning('Web eID revocation checking is switched off; a lost or stolen card would still authenticate');

            return;
        }
        if ($this->ocspClient === null) {
            throw new WebEidException('Revocation checking is on but no OCSP client was supplied');
        }

        try {
            $result = $this->ocspClient->fetch($certificate, $chain->issuerOfLeaf());
        } catch (CertificateRevokedException $exception) {
            // A card reported as revoked, or one the responder has never heard
            // of, is the case this check exists for. Kept apart from a
            // responder that could not be reached, because one is a final
            // answer about the card and the other is a problem of ours.
            throw new WebEidException(
                $exception->reason === CertificateRevokedException::REASON_REVOKED
                    ? 'The card certificate has been revoked'
                    : 'The responder does not recognise the card certificate',
                0,
                $exception,
            );
        } catch (OcspException $exception) {
            throw new WebEidException('The card certificate\'s revocation status could not be established: ' . $exception->getMessage(), 0, $exception);
        }

        foreach ($result->verification->warnings as $warning) {
            $this->logger?->warning('Web eID revocation check: {warning}', ['warning' => $warning]);
        }
    }

    // --- working around the vendor validator --------------------------------

    /**
     * Re-encode an ECDSA signature as DER before the vendor validator sees it.
     *
     * WORKAROUND. Remove this, and its test, once a release of
     * web-eid/web-eid-authtoken-validation-php contains the fix for
     * https://github.com/web-eid/web-eid-authtoken-validation-php/issues/71
     * (pull request #74). Still unreleased in 1.3.1, the current version.
     *
     * A card returns the signature as raw r‖s, each half padded to the width of
     * the curve, so about one half in 256 begins with a zero byte. The vendor's
     * conversion to DER adds a leading zero when the first byte exceeds 0x7f but
     * never removes one that is already there, and DER requires integers in
     * minimal form. OpenSSL then rejects the encoding, so roughly one
     * authentication in 256 fails although the signature is perfectly good. The
     * person tries again and it works, which is why it went unnoticed for so
     * long.
     *
     * Their validator skips its own conversion when the signature already looks
     * like DER, so converting it ourselves, with the encoder the rest of this
     * library uses, avoids the broken path entirely. Only the encoding changes:
     * r and s are the same numbers, verified against the same certificate over
     * the same bytes, so nothing that was refused before is accepted now.
     *
     * Anything unexpected is passed through untouched. This is not the place to
     * repair a malformed token, and the validator will refuse it on its own.
     */
    private static function withDerSignature(string $authToken): string
    {
        $token = json_decode($authToken, true);
        if (!\is_array($token)) {
            return $authToken;
        }
        $algorithm = $token['algorithm'] ?? null;
        $signature = $token['signature'] ?? null;
        if (!\is_string($algorithm) || !\is_string($signature) || !str_starts_with($algorithm, 'ES')) {
            return $authToken;
        }
        $raw = base64_decode($signature, true);
        if ($raw === false || $raw === '' || EcdsaSignature::looksLikeDer($raw)) {
            return $authToken;
        }

        try {
            $token['signature'] = base64_encode(EcdsaSignature::rawToDer($raw));

            return json_encode($token, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return $authToken;
        }
    }

    /**
     * Refuse a token whose certificate nests deeper than any certificate does.
     *
     * The vendor validator hands the certificate to phpseclib before anything
     * here reads it, and phpseclib's decoder exhausts memory on deeply nested
     * DER. That is a fatal error, which the catch in validate() cannot turn into
     * a refused login. The bytes are taken the way phpseclib takes them.
     */
    private static function refuseDeeplyNestedCertificate(string $authToken): void
    {
        $token = json_decode($authToken, true);
        $certificate = \is_array($token) ? ($token['unverifiedCertificate'] ?? null) : null;
        if (!\is_string($certificate) || $certificate === '') {
            return;
        }

        try {
            NestingGuard::check(\phpseclib3\File\ASN1::extractBER($certificate));
        } catch (Asn1Exception $exception) {
            throw new WebEidException('The Web eID token was refused: ' . $exception->getMessage(), 0, $exception);
        }
    }

    // --- the vendor validator ----------------------------------------------

    /**
     * The officially maintained token validator, configured with our anchors
     * and with its own revocation check switched off because allkiri does that
     * part itself.
     */
    private function validator(): AuthTokenValidator
    {
        $builder = (new AuthTokenValidatorBuilder($this->logger))
            ->withSiteOrigin(new Uri($this->configuration->origin->value))
            ->withTrustedCertificateAuthorities(...$this->trustedAuthorities())
            ->withoutUserCertificateRevocationCheckWithOcsp();

        if ($this->configuration->disallowedCertificatePolicies !== []) {
            $builder = $builder->withDisallowedCertificatePolicies(...$this->configuration->disallowedCertificatePolicies);
        }

        return $builder->build();
    }

    /**
     * The certificate authorities from our trust store, in the form the vendor
     * library wants them.
     *
     * @return list<X509>
     */
    private function trustedAuthorities(): array
    {
        $authorities = [];
        foreach ($this->trustStore->anchors([ServiceType::CaQc, ServiceType::CaPkc]) as $anchor) {
            $x509 = new X509();
            if ($x509->loadX509($anchor->certificate->pem()) === false) {
                continue;
            }
            $authorities[] = $x509;
        }

        if ($authorities === []) {
            throw new WebEidException('The trust store holds no certificate authorities, so no card could be trusted');
        }

        return $authorities;
    }

    private function toCertificate(?string $base64): Certificate
    {
        if ($base64 === null || $base64 === '') {
            throw new WebEidException('The Web eID token carries no certificate');
        }

        try {
            return Certificate::fromBase64($base64);
        } catch (CertificateException $exception) {
            throw new WebEidException('The card certificate could not be read: ' . $exception->getMessage(), 0, $exception);
        }
    }

    private function now(): \DateTimeImmutable
    {
        return $this->clock->now()->setTimezone(new \DateTimeZone('UTC'));
    }
}
