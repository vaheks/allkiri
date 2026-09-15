<?php

declare(strict_types=1);

namespace Allkiri\Xml;

/**
 * Bytes that are not XML allkiri will read: empty, not well-formed, or carrying
 * a DOCTYPE.
 */
final class InvalidXmlException extends XmlException {}
