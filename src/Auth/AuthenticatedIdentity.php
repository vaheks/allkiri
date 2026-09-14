<?php

declare(strict_types=1);

namespace Allkiri\Auth;

use Allkiri\Crypto\Certificate;
use Allkiri\Exception\InvalidArgumentException;

/**
 * Who signed in, read from the certificate they authenticated with.
 *
 * Every eID means ends here: Mobile-ID, Smart-ID and the ID-card all produce a
 * certificate, and the application only ever needs the person behind it.
 */
final readonly class AuthenticatedIdentity implements \JsonSerializable
{
    public const VERSION = 2;

    /**
     * @param string $identityCode the identifier without its type and country prefix
     * @param string $country      ISO 3166-1 alpha-2 of the identifier: the country that issued the
     *                             personal code, passport or identity card
     */
    public function __construct(
        public string $identityCode,
        public string $givenName,
        public string $surname,
        public string $country,
        public Certificate $certificate,
        public IdentifierType $identifierType,
    ) {
        if ($identityCode === '') {
            throw new InvalidArgumentException('An authenticated identity needs an identity code');
        }
        if (preg_match('/^[A-Z]{2}$/', $country) !== 1) {
            throw new InvalidArgumentException(\sprintf('An authenticated identity needs a two-letter country, not "%s"', $country));
        }
    }

    /**
     * Estonian certificates put the semantics identifier in the subject's
     * serialNumber as "PNOEE-60001019906", the surname in SN and the given name
     * in GN. That is where these are read from.
     *
     * The identifier keeps its type and its own country. "PASFI-…" is a
     * Finnish passport even in a certificate that says C=EE, and it must not
     * turn into the same account key as a personal code. Only a natural
     * person's identifier counts: PNO, PAS or IDC. An organisation identifier
     * such as "NTREE-…" names no person, and neither does a certificate with no
     * identifier at all, such as an e-seal. Both are refused rather than turned
     * into an account key with nothing in it.
     *
     * Two older forms are still read, as personal codes of the certificate's
     * country: a bare serialNumber, as old cards carry, and a common name in
     * the old three-part form "SURNAME,GIVENNAME,IDENTITYCODE". The profile SK
     * has issued since 2019 writes "GIVENNAME,SURNAME" instead, so a two-part
     * common name says nothing reliable about which half is which and is left
     * alone.
     *
     * @throws UnidentifiableCertificateException when the certificate names no person
     */
    public static function fromCertificate(Certificate $certificate): self
    {
        $commonName = explode(',', $certificate->commonName() ?? '');
        $legacy = \count($commonName) === 3 ? array_map(trim(...), $commonName) : null;
        $serialNumber = trim($certificate->subjectAttribute('serialNumber') ?? '');

        // PNOEE-…, PASEE-…, IDCEE-… (ETSI EN 319 412-1), or NTREE-… and the
        // like for organisations.
        if (preg_match('/^([A-Z]{3})([A-Z]{2})-(.+)$/', $serialNumber, $matches) === 1) {
            $type = IdentifierType::tryFrom($matches[1])
                ?? throw new UnidentifiableCertificateException(\sprintf('The certificate identifies "%s", which is not a person', $serialNumber));
            $country = $matches[2];
            $identityCode = $matches[3];
        } else {
            $type = IdentifierType::PersonalNumber;
            $country = strtoupper($certificate->subjectAttribute('C') ?? '');
            $identityCode = $serialNumber !== '' ? $serialNumber : ($legacy[2] ?? '');
        }

        if ($identityCode === '') {
            throw new UnidentifiableCertificateException('The certificate carries no personal identifier, so it names no person');
        }
        if (preg_match('/^[A-Z]{2}$/', $country) !== 1) {
            throw new UnidentifiableCertificateException('The certificate does not say which country its personal identifier belongs to');
        }

        return new self(
            $identityCode,
            $certificate->subjectAttribute('GN') ?? $legacy[1] ?? '',
            $certificate->subjectAttribute('SN') ?? $legacy[0] ?? '',
            $country,
            $certificate,
            $type,
        );
    }

    /**
     * "Mari-Liis Männik", for showing back to the person who just signed in.
     */
    public function fullName(): string
    {
        return trim($this->givenName . ' ' . $this->surname);
    }

    /**
     * The ETSI semantics identifier, "PNOEE-60001019906", which is what an
     * application should store as the account key. A passport or identity card
     * keeps its own type, "PASEE-…" or "IDCEE-…", so it can never collide with
     * a personal code that happens to have the same number.
     */
    public function semanticsIdentifier(): string
    {
        return \sprintf('%s%s-%s', $this->identifierType->value, $this->country, $this->identityCode);
    }

    /**
     * @return array<string, string|int>
     */
    public function jsonSerialize(): array
    {
        return [
            'version' => self::VERSION,
            'identifierType' => $this->identifierType->value,
            'identityCode' => $this->identityCode,
            'givenName' => $this->givenName,
            'surname' => $this->surname,
            'country' => $this->country,
            'certificate' => $this->certificate->base64(),
        ];
    }
}
