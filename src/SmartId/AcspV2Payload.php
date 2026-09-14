<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

/**
 * What a Smart-ID authentication actually signs.
 *
 * The app does not sign the challenge alone. It signs a pipe-joined string
 * naming the scheme, the protocol, both sides' random values, the relying
 * party, a digest of the dialogues that were offered, the one the app actually
 * showed, where a same-device flow returns, and how the person got there.
 * Verifying the signature over exactly this string is what ties the answer to
 * *this* session on *this* service: a signature lifted from a demo session, or
 * from a session started by someone else, will not verify here even though it
 * is a perfectly good signature.
 *
 * The order of the eleven parts is fixed by the protocol. The tenth is the
 * callback URL of a Web2App or App2App flow, and empty for a QR code or a
 * notification.
 */
final readonly class AcspV2Payload
{
    public const PROTOCOL = 'ACSP_V2';

    /**
     * @param string      $serverRandom             base64, from the session status
     * @param string      $rpChallenge              base64, as it was sent
     * @param string|null $userChallenge            base64url, from the session status; device-link flows only
     * @param string|null $brokeredRelyingPartyName set only when acting for another relying party
     * @param string|null $initialCallbackUrl       the session's callback URL; signed only for Web2App and App2App
     */
    public function __construct(
        public string $scheme,
        public string $serverRandom,
        public string $rpChallenge,
        public ?string $userChallenge,
        public string $relyingPartyNameBase64,
        public ?string $brokeredRelyingPartyName,
        public string $interactionsDigest,
        public InteractionType $interactionTypeUsed,
        public FlowType $flowType,
        public ?string $initialCallbackUrl = null,
    ) {}

    /**
     * The exact bytes the signature covers.
     */
    public function bytes(): string
    {
        $sameDevice = $this->flowType === FlowType::Web2App || $this->flowType === FlowType::App2App;

        return implode('|', [
            $this->scheme,
            self::PROTOCOL,
            $this->serverRandom,
            $this->rpChallenge,
            $this->userChallenge ?? '',
            $this->relyingPartyNameBase64,
            $this->brokeredRelyingPartyName === null ? '' : base64_encode($this->brokeredRelyingPartyName),
            $this->interactionsDigest,
            $this->interactionTypeUsed->value,
            $sameDevice ? ($this->initialCallbackUrl ?? '') : '',
            $this->flowType->value,
        ]);
    }

    /**
     * Assemble the payload for a finished session.
     *
     * @throws SmartIdApiException when the status lacks something the payload needs
     */
    public static function forSession(
        SmartIdConfiguration $configuration,
        SmartIdSession $session,
        SmartIdSessionStatus $status,
        ?string $brokeredRelyingPartyName = null,
    ): self {
        if ($status->serverRandom === null) {
            throw new SmartIdApiException(
                SmartIdApiException::REASON_MALFORMED_RESPONSE,
                'Smart-ID authenticated without returning its own random value, so the signature cannot be checked',
            );
        }
        if ($status->interactionTypeUsed === null || $status->flowType === null) {
            throw new SmartIdApiException(
                SmartIdApiException::REASON_MALFORMED_RESPONSE,
                'Smart-ID authenticated without saying which dialogue was shown or how the app was reached',
            );
        }

        return new self(
            $configuration->scheme,
            $status->serverRandom,
            $session->challengeBase64(),
            $status->userChallenge,
            $configuration->relyingPartyNameBase64(),
            $brokeredRelyingPartyName,
            $session->interactions->digest(),
            $status->interactionTypeUsed,
            $status->flowType,
            $session->initialCallbackUrl,
        );
    }
}
