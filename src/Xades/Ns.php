<?php

declare(strict_types=1);

namespace Allkiri\Xades;

use Allkiri\Xml\Dsig\DsigNs;

/**
 * XAdES namespaces and reference types. XML-DSig's own are in DsigNs.
 *
 * @internal
 */
final class Ns
{
    public const XADES = 'http://uri.etsi.org/01903/v1.3.2#';
    public const XADES141 = 'http://uri.etsi.org/01903/v1.4.1#';

    public const TYPE_SIGNED_PROPERTIES = 'http://uri.etsi.org/01903#SignedProperties';
    public const TYPE_SIGNED_PROPERTIES_V111 = 'http://uri.etsi.org/01903/v1.1.1#SignedProperties';

    /** The prefixes XAdES queries use, XML-DSig's included. */
    public const PREFIXES = [
        'ds' => DsigNs::DS,
        'ec' => DsigNs::C14N_EXC,
        'xades' => self::XADES,
        'xadesv141' => self::XADES141,
    ];

    private function __construct() {}
}
