<?php

declare(strict_types=1);

namespace Allkiri\Signing;

/**
 * The certificate cannot make a signature that would validate: an
 * authentication certificate whose key usage lacks nonRepudiation, or one with
 * a key of a type allkiri cannot sign with.
 *
 * Raised before anything is built, so nobody is asked for a PIN and no
 * timestamp is paid for.
 */
final class CertificateNotForSigningException extends SigningException {}
