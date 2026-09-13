<?php

declare(strict_types=1);

namespace Allkiri\Container\Zip;

use Allkiri\Container\InvalidContainerException;

/**
 * A container that would expand out of all proportion to its size.
 *
 * Nothing about such an archive is malformed, which is the point: a few
 * hundred kilobytes can declare gigabytes of content, and a server that
 * accepts containers from strangers will run out of memory long before it
 * discovers there was nothing worth reading.
 *
 * Separate from {@see InvalidContainerException}'s other causes so that an
 * application can tell a hostile upload from a broken one.
 */
final class ZipBombException extends InvalidContainerException {}
