<?php

declare(strict_types=1);

namespace Allkiri\Signing;

/**
 * The signature was prepared too long ago to be finished. Prepare it again.
 *
 * Raised before a timestamp is bought, so the refusal costs nothing.
 */
final class PreparedSignatureExpiredException extends SigningException {}
