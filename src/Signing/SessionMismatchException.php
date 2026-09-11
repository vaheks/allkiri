<?php

declare(strict_types=1);

namespace Allkiri\Signing;

/**
 * A signing session was finished against something other than what it started
 * against: different files, a container that gained a signature meanwhile, or
 * a mutated prepared document.
 */
final class SessionMismatchException extends SigningException {}
