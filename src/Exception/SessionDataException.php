<?php

declare(strict_types=1);

namespace Allkiri\Exception;

/**
 * Something kept between requests could not be read back: a prepared
 * signature, a session or a challenge.
 *
 * It came from the application's store rather than from its code, so the
 * useful response is to start the flow again. The message says what was being
 * read and, when the problem is with one field, which.
 */
final class SessionDataException extends \RuntimeException implements AllkiriException {}
