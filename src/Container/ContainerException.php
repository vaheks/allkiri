<?php

declare(strict_types=1);

namespace Allkiri\Container;

use Allkiri\Exception\AllkiriException;

/**
 * A container could not be read or written.
 */
class ContainerException extends \RuntimeException implements AllkiriException {}
