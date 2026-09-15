<?php

declare(strict_types=1);

namespace Allkiri\Trust;

use Allkiri\Exception\AllkiriException;

/**
 * Base of the trust layer's failures (trusted lists, anchors, chains).
 */
class TrustException extends \RuntimeException implements AllkiriException {}
