<?php

declare(strict_types=1);

namespace Allkiri\Container\Zip;

use Allkiri\Container\InvalidContainerException;

/**
 * A ZIP feature allkiri deliberately does not read: ZIP64, encryption,
 * multi-disk archives, compression other than store and deflate.
 */
final class UnsupportedZipException extends InvalidContainerException {}
