<?php

declare(strict_types=1);

namespace Allkiri\Trust;

/**
 * Trust service types (ETSI TS 119 612 §5.5.1) allkiri cares about.
 */
enum ServiceType: string
{
    case CaQc = 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC';
    case CaPkc = 'http://uri.etsi.org/TrstSvc/Svctype/CA/PKC';
    case OcspQc = 'http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC';
    case Ocsp = 'http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP';
    case TsaQtst = 'http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST';
    case TsaTssQc = 'http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC';
    case TsaTssAdes = 'http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-AdESQCandQES';
    case Tsa = 'http://uri.etsi.org/TrstSvc/Svctype/TSA';

    public function isCa(): bool
    {
        return $this === self::CaQc || $this === self::CaPkc;
    }

    public function isOcsp(): bool
    {
        return $this === self::OcspQc || $this === self::Ocsp;
    }

    public function isTsa(): bool
    {
        return \in_array($this, [self::TsaQtst, self::TsaTssQc, self::TsaTssAdes, self::Tsa], true);
    }

    /**
     * @return list<self>
     */
    public static function caTypes(): array
    {
        return [self::CaQc, self::CaPkc];
    }

    /**
     * @return list<self>
     */
    public static function tsaTypes(): array
    {
        return [self::TsaQtst, self::TsaTssQc, self::TsaTssAdes, self::Tsa];
    }

    /**
     * @return list<self>
     */
    public static function ocspTypes(): array
    {
        return [self::OcspQc, self::Ocsp];
    }
}
