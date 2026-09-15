<?php

declare(strict_types=1);

namespace Allkiri\Signing;

/**
 * The certificate cannot make a signature that would validate, such as an
 * authentication certificate whose key usage lacks nonRepudiation.
 *
 * Raised before anything is built, so nobody is asked for a PIN and no
 * timestamp is paid for.
 */
final class CertificateNotForSigningException extends SigningException {}
