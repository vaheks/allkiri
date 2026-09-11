<?php

declare(strict_types=1);

namespace Allkiri\Signing;

use Allkiri\Crypto\Certificate;

/**
 * A signer that can answer within one request: a local key or an e-seal.
 *
 * Web eID, Mobile-ID and Smart-ID cannot implement this, because the person
 * has to act in between; they use {@see SigningService::prepare()} and
 * {@see SigningService::finalize()} directly.
 */
interface Signer
{
    public function certificate(): Certificate;

    /**
     * @return string the signature value in XML-DSig wire format: raw r‖s for ECDSA
     */
    public function sign(DataToBeSigned $dataToBeSigned): string;
}
