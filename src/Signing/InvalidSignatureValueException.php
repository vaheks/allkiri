<?php

declare(strict_types=1);

namespace Allkiri\Signing;

/**
 * The signature value does not verify against the signer's certificate.
 *
 * Caught before any timestamp or OCSP request, so a wrong value costs nothing
 * and cannot produce a container that only fails later, in a validator.
 */
final class InvalidSignatureValueException extends SigningException {}
