<?php

declare(strict_types=1);

namespace Allkiri\Exception;

/**
 * Every exception allkiri throws implements this.
 *
 * Catch it to handle any library failure, or catch a module's base class (Http,
 * Crypto, Trust, Container, Xades, Signing, MobileId, SmartId, WebEid) for finer
 * control. A programmer or configuration error is also SPL's
 * `\InvalidArgumentException`; everything else is a `\RuntimeException`.
 */
interface AllkiriException extends \Throwable {}
