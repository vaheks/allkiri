<?php

declare(strict_types=1);

namespace Allkiri\Auth;

use Allkiri\Crypto\Certificate;

/**
 * Who signed in, read from the certificate they authenticated with.
 *
 * Every eID means ends here: Mobile-ID, Smart-ID and the ID-card all produce a
 * certificate, and the application only ever needs the person behind it.
 */
final readonly class AuthenticatedIdentity implements \JsonSerializable
{
    public const VERSION = 1;

    /**
     * @param string $identityCode the national identity number without the country prefix
     * @param string $country      ISO 3166-1 alpha-2, from the certificate's country attribute
     */
    public function __construct(
        public string $identityCode,
        public string $givenName,
        public string $surname,
        public string $country,
        public Certificate $certificate,
    ) {}

    /**
     * Estonian certificates put the semantics identifier in the subject's
     * serialNumber as "PNOEE-60001019906", the surname in SN, the given name in
     * GN and the country in C. That is where these are read from.
     *
     * The common name is only a fallback, and only in its old three-part form
     * "SURNAME,GIVENNAME,IDENTITYCODE". The profile SK has issued since 2019
     * writes "GIVENNAME,SURNAME" instead, so a two-part common name says
     * nothing reliable about which half is which and is left alone.
     */
    public static function fromCertificate(Certificate $certificate): self
    {
        $commonName = explode(',', $certificate->commonName() ?? '');
        $legacy = \count($commonName) === 3 ? array_map(trim(...), $commonName) : null;

        $serialNumber = $certificate->subjectAttribute('serialNumber') ?? '';
        // PNOEE-… (ETSI EN 319 412-1), PASEE-…, IDCEE-…, or a bare code on old cards.
        $identityCode = preg_match('/^[A-Z]{3}[A-Z]{2}-(.+)$/', $serialNumber, $matches) === 1
            ? $matches[1]
            : ($serialNumber !== '' ? $serialNumber : ($legacy[2] ?? ''));

        $country = $certificate->subjectAttribute('C') ?? '';
        if ($country === '' && preg_match('/^[A-Z]{3}([A-Z]{2})-/', $serialNumber, $matches) === 1) {
            $country = $matches[1];
        }

        return new self(
            $identityCode,
            $certificate->subjectAttribute('GN') ?? $legacy[1] ?? '',
            $certificate->subjectAttribute('SN') ?? $legacy[0] ?? '',
            strtoupper($country),
            $certificate,
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
     * application should store as the account key.
     */
    public function semanticsIdentifier(): string
    {
        return \sprintf('PNO%s-%s', $this->country, $this->identityCode);
    }

    /**
     * @return array<string, string|int>
     */
    public function jsonSerialize(): array
    {
        return [
            'version' => self::VERSION,
            'identityCode' => $this->identityCode,
            'givenName' => $this->givenName,
            'surname' => $this->surname,
            'country' => $this->country,
            'certificate' => $this->certificate->base64(),
        ];
    }
}
