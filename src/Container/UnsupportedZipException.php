<?php

declare(strict_types=1);

namespace Allkiri\Container;

/**
 * A ZIP feature allkiri deliberately does not read or write: ZIP64,
 * encryption, multi-disk archives, compression other than store and deflate.
 */
final class UnsupportedZipException extends InvalidContainerException {}
