<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Crypto\Certificate;

/**
 * One answer to "is the person done yet?".
 *
 * While the app is still showing the request the state is RUNNING and
 * everything else is null. When it turns COMPLETE the end result says what
 * happened, and on OK the signature and the certificate are present.
 */
final readonly class SmartIdSessionStatus
{
    public const STATE_RUNNING = 'RUNNING';
    public const STATE_COMPLETE = 'COMPLETE';

    /**
     * @param string|null $signatureValue raw signature bytes, already base64-decoded
     * @param string|null $serverRandom   base64, part of the authenticated payload
     * @param string|null $userChallenge  base64url, present in device-link flows
     */
    public function __construct(
        public string $state,
        public ?SmartIdEndResult $result = null,
        public ?DocumentNumber $documentNumber = null,
        public ?string $signatureValue = null,
        public ?string $signatureAlgorithmName = null,
        public ?RsaPssParameters $pssParameters = null,
        public ?Certificate $certificate = null,
        public ?CertificateLevel $certificateLevel = null,
        public ?string $serverRandom = null,
        public ?string $userChallenge = null,
        public ?FlowType $flowType = null,
        public ?InteractionType $interactionTypeUsed = null,
        public ?InteractionType $refusedInteraction = null,
        public ?string $deviceIpAddress = null,
        public ?string $signatureProtocol = null,
    ) {}

    public function isComplete(): bool
    {
        return $this->state === self::STATE_COMPLETE;
    }

    public function isRunning(): bool
    {
        return !$this->isComplete();
    }

    public function isOk(): bool
    {
        return $this->result === SmartIdEndResult::Ok;
    }

    /**
     * Turn anything other than OK into the exception that explains it.
     *
     * @throws SmartIdSessionException
     */
    public function requireOk(): self
    {
        if (!$this->isOk()) {
            throw new SmartIdSessionException($this->result ?? SmartIdEndResult::Timeout, $this->refusedInteraction);
        }

        return $this;
    }

    /**
     * Whether PKCS#1 v1.5 was used rather than PSS. SK deprecates it; a
     * signature that arrives this way still has to be described correctly.
     */
    public function isLegacyRsa(): bool
    {
        return $this->pssParameters === null && $this->signatureAlgorithmName !== null;
    }
}
