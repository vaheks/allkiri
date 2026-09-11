<?php

declare(strict_types=1);

namespace Allkiri\Crypto\Asn1;

use Allkiri\Crypto\CryptoException;

/**
 * DER could not be decoded, did not match the expected structure, or a
 * value could not be encoded.
 */
final class Asn1Exception extends CryptoException {}
