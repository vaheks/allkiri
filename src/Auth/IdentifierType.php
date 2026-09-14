<?php

declare(strict_types=1);

namespace Allkiri\Auth;

/**
 * What kind of number a natural person's semantics identifier carries, as
 * ETSI EN 319 412-1 defines them: a personal code, a passport number or an
 * identity card number.
 *
 * The Smart-ID API knows the same three. They are repeated here rather than
 * shared, because signing in does not depend on any one eID means.
 */
enum IdentifierType: string
{
    case PersonalNumber = 'PNO';
    case Passport = 'PAS';
    case IdentityCard = 'IDC';
}
