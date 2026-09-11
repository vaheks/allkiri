<?php

declare(strict_types=1);

namespace Allkiri\MobileId;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\SignatureAlgorithm;

/**
 * One answer to "is the person done yet?".
 *
 * While the phone is still showing the request the state is RUNNING and
 * everything else is null. When it turns COMPLETE the result says what
 * happened, and on {@see MobileIdResult::Ok} the signature is present.
 */
final readonly class MobileIdSessionStatus
{
    public const STATE_RUNNING = 'RUNNING';
    public const STATE_COMPLETE = 'COMPLETE';

    /**
     * @param string|null $signatureValue raw signature bytes, already base64-decoded
     * @param Certificate|null $certificate present for authentication sessions only
     */
    public function __construct(
        public string $state,
        public ?MobileIdResult $result = null,
        public ?string $signatureValue = null,
        public ?SignatureAlgorithm $signatureAlgorithm = null,
        public ?Certificate $certificate = null,
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
        return $this->result === MobileIdResult::Ok;
    }

    /**
     * The signature, or an exception saying why there is none.
     *
     * @throws MobileIdSessionException when the person did not sign
     */
    public function requireSignature(): string
    {
        if ($this->signatureValue === null || $this->signatureValue === '') {
            throw new MobileIdSessionException($this->result ?? MobileIdResult::Timeout);
        }

        return $this->signatureValue;
    }
}
