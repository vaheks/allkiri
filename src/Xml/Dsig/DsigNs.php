<?php

declare(strict_types=1);

namespace Allkiri\Xml\Dsig;

/**
 * The XML-DSig namespace and the canonicalisation and transform algorithms,
 * which XAdES signatures and trusted lists share.
 */
final class DsigNs
{
    public const DS = 'http://www.w3.org/2000/09/xmldsig#';

    public const C14N_EXC = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    public const C14N_EXC_WITH_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';
    public const C14N_10 = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    public const C14N_10_WITH_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
    public const C14N_11 = 'http://www.w3.org/2006/12/xml-c14n11';
    public const C14N_11_WITH_COMMENTS = 'http://www.w3.org/2006/12/xml-c14n11#WithComments';

    public const TRANSFORM_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    /** The prefixes XML-DSig queries use: ds, and ec for InclusiveNamespaces. */
    public const PREFIXES = ['ds' => self::DS, 'ec' => self::C14N_EXC];

    private function __construct() {}
}
