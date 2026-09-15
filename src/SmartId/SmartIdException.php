<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Exception\AllkiriException;

/**
 * Anything that went wrong with Smart-ID.
 */
class SmartIdException extends \RuntimeException implements AllkiriException {}
