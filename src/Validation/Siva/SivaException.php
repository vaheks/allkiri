<?php

declare(strict_types=1);

namespace Allkiri\Validation\Siva;

use Allkiri\Exception\AllkiriException;

/**
 * SiVa could not be reached or did not answer in a way we can read.
 */
final class SivaException extends \RuntimeException implements AllkiriException {}
