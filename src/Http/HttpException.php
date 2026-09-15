<?php

declare(strict_types=1);

namespace Allkiri\Http;

use Allkiri\Exception\AllkiriException;

/**
 * Base of the HTTP layer's exceptions.
 */
class HttpException extends \RuntimeException implements AllkiriException {}
