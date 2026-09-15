<?php

declare(strict_types=1);

namespace Allkiri\Exception;

/**
 * A caller passed something the library cannot work with: a programmer or
 * configuration error, not a failure at run time.
 */
final class InvalidArgumentException extends \InvalidArgumentException implements AllkiriException {}
