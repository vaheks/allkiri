<?php

declare(strict_types=1);

namespace Allkiri\Container;

/**
 * The bytes are not a container at all: not a ZIP, not well-formed, or a ZIP
 * allkiri refuses to read. Structural problems that a report can explain are
 * findings instead, not exceptions.
 */
class InvalidContainerException extends ContainerException {}
