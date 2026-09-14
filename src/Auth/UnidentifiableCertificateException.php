<?php

declare(strict_types=1);

namespace Allkiri\Auth;

use Allkiri\Exception\AllkiriException;

/**
 * A certificate that authenticated but names no person to sign in as: an
 * e-seal, an organisation, or a certificate without a personal identifier.
 */
final class UnidentifiableCertificateException extends AllkiriException {}
