<?php

declare(strict_types=1);

namespace Allkiri\Exception;

/**
 * Root of every exception thrown by allkiri.
 *
 * Catch this to handle any library failure; catch the per-module subclasses
 * (Http, Crypto, Trust, Container, Xades, Signing) for finer control.
 */
abstract class AllkiriException extends \RuntimeException {}
