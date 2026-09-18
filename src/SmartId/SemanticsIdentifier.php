<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Exception\InvalidArgumentException;

/**
 * Who a person is, in the form ETSI EN 319 412-1 defines and Smart-ID uses to
 * address them: "PNOEE-40504040001".
 *
 * A person may have several Smart-ID accounts; addressing them this way lets
 * the service pick, where a document number names one exactly.
 */
final readonly class SemanticsIdentifier implements \Stringable
{
    public const TYPE_PERSONAL_NUMBER = 'PNO';
    public const TYPE_PASSPORT = 'PAS';
    public const TYPE_IDENTITY_CARD = 'IDC';

    public function __construct(
        public string $identityType,
        public string $country,
        public string $identityNumber,
    ) {
        if (!\in_array($identityType, [self::TYPE_PERSONAL_NUMBER, self::TYPE_PASSPORT, self::TYPE_IDENTITY_CARD], true)) {
            throw new InvalidArgumentException(\sprintf('Unknown identity type "%s"; expected PNO, PAS or IDC', $identityType));
        }
        if (preg_match('/^[A-Z]{2}\z/', $country) !== 1) {
            throw new InvalidArgumentException('The country must be a two-letter upper-case ISO 3166-1 alpha-2 code');
        }
        // Latvian numbers carry a hyphen: "050405-10009".
        if (preg_match('/^[A-Za-z0-9\-]{1,}\z/', $identityNumber) !== 1) {
            throw new InvalidArgumentException('The identity number must not be empty and may contain only letters, digits and hyphens');
        }
    }

    /**
     * The usual case: a national personal code.
     */
    public static function personalNumber(string $country, string $identityNumber): self
    {
        return new self(self::TYPE_PERSONAL_NUMBER, strtoupper($country), $identityNumber);
    }

    public static function estonian(string $identityNumber): self
    {
        return self::personalNumber('EE', $identityNumber);
    }

    /**
     * Parse "PNOEE-40504040001".
     */
    public static function parse(string $identifier): self
    {
        if (preg_match('/^(PNO|PAS|IDC)([A-Z]{2})-(.+)\z/', $identifier, $matches) !== 1) {
            throw new InvalidArgumentException(\sprintf('"%s" is not a semantics identifier such as PNOEE-40504040001', $identifier));
        }

        return new self($matches[1], $matches[2], $matches[3]);
    }

    public function __toString(): string
    {
        return $this->identityType . $this->country . '-' . $this->identityNumber;
    }
}
