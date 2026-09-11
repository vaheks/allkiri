<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

use Allkiri\Auth\AuthenticatedIdentity;
use Allkiri\Clock\SystemClock;
use Allkiri\Crypto\CryptoException;
use Allkiri\Crypto\EcdsaSignature;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\KeyType;
use Allkiri\Crypto\NonceGenerator;
use Allkiri\Crypto\PublicKeyVerifier;
use Allkiri\Crypto\RandomNonceGenerator;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Trust\ChainBuilder;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustException;
use phpseclib3\Crypt\EC;
use Psr\Clock\ClockInterface;

/**
 * Signing in with Mobile-ID.
 *
 * Two steps, because a person and a phone sit between them: `start()` returns
 * a session carrying the four-digit verification code to show, and
 * `complete()` turns a finished session into the person's identity.
 *
 * The challenge is random data, and the phone signs its digest. Nothing about
 * the person is trusted until that signature verifies against the certificate
 * the service returned, and that certificate chains to a trust anchor.
 */
final class MobileIdAuthenticator
{
    private const CHALLENGE_BYTES = 64;

    public function __construct(
        private readonly MobileIdClient $client,
        private readonly ?ChainBuilder $chainBuilder = null,
        private readonly HashAlgorithm $hashAlgorithm = HashAlgorithm::SHA256,
        private readonly NonceGenerator $nonceGenerator = new RandomNonceGenerator(),
        private readonly ClockInterface $clock = new SystemClock(),
        private readonly PublicKeyVerifier $verifier = new PublicKeyVerifier(),
    ) {}

    /**
     * Ask the person to authenticate.
     *
     * Show `$session->verificationCode` immediately: it is the only protection
     * against someone starting a session in the person's name and having them
     * approve it. Store the session, it is JSON-serialisable.
     */
    public function start(MobileIdIdentity $identity): MobileIdSession
    {
        $challenge = $this->nonceGenerator->generate(self::CHALLENGE_BYTES);
        $hash = $this->hashAlgorithm->digest($challenge);
        $sessionId = $this->client->startAuthentication($identity, $hash, $this->hashAlgorithm);

        return new MobileIdSession(
            $sessionId,
            MobileIdSession::TYPE_AUTHENTICATION,
            VerificationCode::forHash($hash),
            $identity,
            $challenge,
        );
    }

    /**
     * Ask once whether the person is done. Null means they are not yet.
     *
     * @throws MobileIdSessionException when they cancelled, or could not be reached
     */
    public function poll(MobileIdSession $session): ?AuthenticatedIdentity
    {
        $status = $this->client->status($session->type, $session->sessionId);
        if ($status->isRunning()) {
            return null;
        }
        if (!$status->isOk()) {
            throw new MobileIdSessionException($status->result ?? MobileIdResult::Timeout);
        }

        return $this->complete($session, $status);
    }

    /**
     * Block until the person answers. Suitable for a console tool or a worker,
     * not for a web request.
     */
    public function authenticate(MobileIdIdentity $identity, ?MobileIdPoller $poller = null): AuthenticatedIdentity
    {
        $session = $this->start($identity);

        return $this->complete($session, ($poller ?? new MobileIdPoller($this->client))->wait($session));
    }

    /**
     * Check a finished session and return who it proves was there.
     */
    public function complete(MobileIdSession $session, MobileIdSessionStatus $status): AuthenticatedIdentity
    {
        if ($session->type !== MobileIdSession::TYPE_AUTHENTICATION) {
            throw new MobileIdException('This session is a signing session, not an authentication');
        }
        if (!$status->isOk()) {
            throw new MobileIdSessionException($status->result ?? MobileIdResult::Timeout);
        }
        $certificate = $status->certificate
            ?? throw new MobileIdApiException(MobileIdApiException::REASON_MALFORMED_RESPONSE, 'Mobile-ID authenticated without returning a certificate');
        $signature = $status->requireSignature();

        // The service chooses the signature algorithm; take the hash we asked
        // for and the key we were given, and refuse anything else.
        $algorithm = $this->algorithmFor($certificate->keyType());
        if ($status->signatureAlgorithm !== null && $status->signatureAlgorithm !== $algorithm) {
            throw new MobileIdException(\sprintf(
                'Mobile-ID signed with %s but the request asked for %s',
                $status->signatureAlgorithm->value,
                $algorithm->value,
            ));
        }

        // Mobile-ID DER-encodes ECDSA values; everything here verifies r‖s.
        $key = $certificate->publicKey();
        if ($key instanceof EC) {
            try {
                $signature = EcdsaSignature::toRaw($signature, $key);
            } catch (CryptoException $exception) {
                throw new MobileIdException('The Mobile-ID signature is not a usable ECDSA value: ' . $exception->getMessage(), 0, $exception);
            }
        }

        if (!$this->verifier->verify($key, $algorithm, $session->challenge, $signature)) {
            throw new MobileIdException('The Mobile-ID signature does not match the challenge; this session proves nothing');
        }

        $now = $this->clock->now();
        if (!$certificate->isValidAt($now)) {
            throw new MobileIdException('The Mobile-ID certificate is not valid at this moment');
        }
        if ($this->chainBuilder !== null) {
            try {
                $this->chainBuilder->build($certificate, [], $now, [ServiceType::CaQc, ServiceType::CaPkc]);
            } catch (TrustException $exception) {
                throw new MobileIdException('The Mobile-ID certificate does not chain to a trusted authority: ' . $exception->getMessage(), 0, $exception);
            }
        }

        $identity = AuthenticatedIdentity::fromCertificate($certificate);
        if ($identity->identityCode !== $session->identity->nationalIdentityNumber) {
            throw new MobileIdException(\sprintf(
                'Mobile-ID answered for %s but the session was started for %s',
                $identity->identityCode,
                $session->identity->nationalIdentityNumber,
            ));
        }

        return $identity;
    }

    private function algorithmFor(KeyType $keyType): SignatureAlgorithm
    {
        $bits = match ($this->hashAlgorithm) {
            HashAlgorithm::SHA256 => '256',
            HashAlgorithm::SHA384 => '384',
            HashAlgorithm::SHA512 => '512',
        };

        // Mobile-ID signs the digest with PKCS#1 v1.5 for RSA keys.
        return SignatureAlgorithm::from(($keyType === KeyType::EC ? 'ES' : 'RS') . $bits);
    }
}
