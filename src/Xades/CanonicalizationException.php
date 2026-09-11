<?php

declare(strict_types=1);

namespace Allkiri\Xades;

/**
 * A canonicalisation algorithm allkiri cannot run (C14N 1.1 is the usual one:
 * ext-dom offers only inclusive 1.0 and exclusive 1.0).
 */
final class CanonicalizationException extends XadesException {}
