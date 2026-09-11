<?php

declare(strict_types=1);

namespace Allkiri\Trust;

/**
 * Trust service statuses (ETSI TS 119 612 §5.5.4), current and pre-eIDAS.
 */
enum ServiceStatus: string
{
    case Granted = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
    case Withdrawn = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn';
    case RecognisedAtNationalLevel = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel';
    case DeprecatedAtNationalLevel = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel';
    case UnderSupervision = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision';
    case SupervisionInCessation = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation';
    case SupervisionCeased = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionceased';
    case SupervisionRevoked = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionrevoked';
    case Accredited = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited';
    case AccreditationCeased = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationceased';
    case AccreditationRevoked = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked';
    case SetByNationalLaw = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/setbynationallaw';
    case DeprecatedByNationalLaw = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedbynationallaw';

    /**
     * Whether certificates issued under this status may be trusted.
     */
    public function isTrustworthy(): bool
    {
        return match ($this) {
            self::Granted, self::RecognisedAtNationalLevel, self::UnderSupervision, self::SupervisionInCessation, self::Accredited, self::SetByNationalLaw => true,
            default => false,
        };
    }
}
