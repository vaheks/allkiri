<?php

declare(strict_types=1);

namespace Allkiri\Xades;

use Allkiri\Exception\AllkiriException;

/**
 * Base of the XML signature layer's failures.
 */
class XadesException extends \RuntimeException implements AllkiriException {}
