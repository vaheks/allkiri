<?php

declare(strict_types=1);

namespace Allkiri\Crypto;

use Allkiri\Exception\AllkiriException;

/**
 * Base of the cryptographic layer's exceptions (ASN.1, certificates, OCSP, timestamps).
 */
class CryptoException extends \RuntimeException implements AllkiriException {}
