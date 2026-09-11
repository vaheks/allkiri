<?php

declare(strict_types=1);

namespace Allkiri\Xades;

/**
 * Namespaces and algorithm identifiers used in ASiC-E / XAdES documents.
 */
final class Ns
{
    public const DS = 'http://www.w3.org/2000/09/xmldsig#';
    public const XADES = 'http://uri.etsi.org/01903/v1.3.2#';
    public const XADES141 = 'http://uri.etsi.org/01903/v1.4.1#';
    public const ASIC = 'http://uri.etsi.org/02918/v1.2.1#';
    public const MANIFEST = 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0';

    public const C14N_EXC = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    public const C14N_EXC_WITH_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';
    public const C14N_10 = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    public const C14N_10_WITH_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
    public const C14N_11 = 'http://www.w3.org/2006/12/xml-c14n11';
    public const C14N_11_WITH_COMMENTS = 'http://www.w3.org/2006/12/xml-c14n11#WithComments';

    public const TRANSFORM_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    public const TYPE_SIGNED_PROPERTIES = 'http://uri.etsi.org/01903#SignedProperties';
    public const TYPE_SIGNED_PROPERTIES_V111 = 'http://uri.etsi.org/01903/v1.1.1#SignedProperties';

    public const MIME_ASICE = 'application/vnd.etsi.asic-e+zip';

    private function __construct() {}
}
