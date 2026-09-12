<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Exception\InvalidArgumentException;

/**
 * One Smart-ID account, exactly: "PNOEE-40504040001-MOCK-Q".
 *
 * A session reports the document number it used, and it is the only way to
 * fetch a certificate without asking the person anything, so an application
 * that will later want to sign should store it when they first sign in.
 */
final readonly class DocumentNumber implements \Stringable
{
    public function __construct(public string $value)
    {
        // The middle part varies (MOCK, DEMO, DEM0, DEM2, NQ suffixes and so
        // on), so only the shape is checked, not the vocabulary.
        if (preg_match('/^(PNO|PAS|IDC)[A-Z]{2}-[A-Za-z0-9\-]+-[A-Za-z0-9]+-[A-Za-z0-9]+$/', $value) !== 1) {
            throw new InvalidArgumentException(\sprintf('"%s" is not a Smart-ID document number such as PNOEE-40504040001-MOCK-Q', $value));
        }
    }

    /**
     * The person the account belongs to.
     */
    public function semanticsIdentifier(): SemanticsIdentifier
    {
        $parts = explode('-', $this->value);
        // Everything between the prefix and the last two parts is the identity
        // number, which may itself contain a hyphen in Latvia.
        $identityNumber = implode('-', \array_slice($parts, 1, \count($parts) - 3));

        return SemanticsIdentifier::parse($parts[0] . '-' . $identityNumber);
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
