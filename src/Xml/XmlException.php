<?php

declare(strict_types=1);

namespace Allkiri\Xml;

use Allkiri\Exception\AllkiriException;

/**
 * Base of the failures of an XML document: bytes that are not XML, a
 * canonicalisation that cannot be run, and the XAdES layer's own.
 */
class XmlException extends \RuntimeException implements AllkiriException {}
