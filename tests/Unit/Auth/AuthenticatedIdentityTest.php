<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Auth;

use Allkiri\Auth\AuthenticatedIdentity;
use Allkiri\Auth\IdentifierType;
use Allkiri\Auth\UnidentifiableCertificateException;
use Allkiri\Exception\InvalidArgumentException;
use Allkiri\Tests\Support\Pki\TestCertificates;
use Allkiri\Tests\Support\Pki\TestPki;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The account key an application stores comes from here, so every way a
 * certificate can name a person, and every way it can fail to, is pinned.
 */
#[CoversClass(AuthenticatedIdentity::class)]
final class AuthenticatedIdentityTest extends TestCase
{
    public function testTheCurrentProfileIsReadFromTheSerialNumberAndTheNames(): void
    {
        $identity = AuthenticatedIdentity::fromCertificate(TestPki::cardAuth()->certificate);

        self::assertSame(IdentifierType::PersonalNumber, $identity->identifierType);
        self::assertSame('38001085718', $identity->identityCode);
        self::assertSame('EE', $identity->country);
        self::assertSame('JAAK-KRISTJAN', $identity->givenName);
        self::assertSame('JOEORG', $identity->surname);
        self::assertSame('JAAK-KRISTJAN JOEORG', $identity->fullName());
        self::assertSame('PNOEE-38001085718', $identity->semanticsIdentifier());
    }

    /**
     * @return iterable<string, array{array<string, string>, IdentifierType, string, string}>
     */
    public static function identifiers(): iterable
    {
        yield 'a passport' => [['id-at-countryName' => 'EE', 'id-at-serialNumber' => 'PASEE-K1234567'], IdentifierType::Passport, 'K1234567', 'PASEE-K1234567'];
        yield 'an identity card' => [['id-at-countryName' => 'EE', 'id-at-serialNumber' => 'IDCEE-AB1234567'], IdentifierType::IdentityCard, 'AB1234567', 'IDCEE-AB1234567'];
        yield 'a foreign passport in a certificate that says EE' => [['id-at-countryName' => 'EE', 'id-at-serialNumber' => 'PASFI-X9876543'], IdentifierType::Passport, 'X9876543', 'PASFI-X9876543'];
        yield 'a bare personal code, as old cards carry' => [['id-at-countryName' => 'EE', 'id-at-serialNumber' => '38001085718'], IdentifierType::PersonalNumber, '38001085718', 'PNOEE-38001085718'];
        yield 'the old three-part common name' => [['id-at-countryName' => 'EE', 'id-at-commonName' => 'JOEORG,JAAK-KRISTJAN,38001085718'], IdentifierType::PersonalNumber, '38001085718', 'PNOEE-38001085718'];
    }

    /**
     * @param array<string, string> $subject
     */
    #[DataProvider('identifiers')]
    public function testEachKindOfIdentifierKeepsItsTypeAndItsCountry(array $subject, IdentifierType $type, string $code, string $semanticsIdentifier): void
    {
        $identity = AuthenticatedIdentity::fromCertificate(TestCertificates::issue(TestPki::cardAuth(), $subject)->certificate);

        self::assertSame($type, $identity->identifierType);
        self::assertSame($code, $identity->identityCode);
        self::assertSame($semanticsIdentifier, $identity->semanticsIdentifier());
    }

    public function testTheOldThreePartCommonNameAlsoGivesTheNames(): void
    {
        $identity = AuthenticatedIdentity::fromCertificate(TestCertificates::issue(TestPki::cardAuth(), [
            'id-at-countryName' => 'EE',
            'id-at-commonName' => 'JOEORG,JAAK-KRISTJAN,38001085718',
        ])->certificate);

        self::assertSame('JAAK-KRISTJAN', $identity->givenName);
        self::assertSame('JOEORG', $identity->surname);
    }

    public function testATwoPartCommonNameIsNotGuessedAt(): void
    {
        // SK's current profile writes GIVENNAME,SURNAME and the old one wrote
        // SURNAME,GIVENNAME, so two parts cannot say which is which.
        $identity = AuthenticatedIdentity::fromCertificate(TestCertificates::issue(TestPki::cardAuth(), [
            'id-at-countryName' => 'EE',
            'id-at-commonName' => 'JAAK-KRISTJAN,JOEORG',
            'id-at-serialNumber' => 'PNOEE-38001085718',
        ])->certificate);

        self::assertSame('', $identity->givenName);
        self::assertSame('', $identity->surname);
        self::assertSame('PNOEE-38001085718', $identity->semanticsIdentifier());
    }

    /**
     * @return iterable<string, array{array<string, string>, string}>
     */
    public static function certificatesNamingNoPerson(): iterable
    {
        yield 'an organisation identifier' => [['id-at-countryName' => 'EE', 'id-at-organizationName' => 'Allkiri OÜ', 'id-at-serialNumber' => 'NTREE-10747013'], 'not a person'];
        yield 'no identifier at all' => [['id-at-countryName' => 'EE', 'id-at-commonName' => 'Allkiri test e-seal'], 'no personal identifier'];
        yield 'a two-part common name alone' => [['id-at-countryName' => 'EE', 'id-at-commonName' => 'JAAK-KRISTJAN,JOEORG'], 'no personal identifier'];
        yield 'a bare code with no country' => [['id-at-serialNumber' => '38001085718'], 'which country'];
    }

    /**
     * @param array<string, string> $subject
     */
    #[DataProvider('certificatesNamingNoPerson')]
    public function testACertificateThatNamesNoPersonIsRefused(array $subject, string $reason): void
    {
        $certificate = TestCertificates::issue(TestPki::cardAuth(), $subject)->certificate;

        $this->expectException(UnidentifiableCertificateException::class);
        $this->expectExceptionMessage($reason);

        AuthenticatedIdentity::fromCertificate($certificate);
    }

    public function testTheCommittedESealIsRefused(): void
    {
        // It once came back as identity code "" and account key "PNOEE-",
        // which every certificate without a personal code would have shared.
        $this->expectException(UnidentifiableCertificateException::class);

        AuthenticatedIdentity::fromCertificate(TestPki::signerRsa()->certificate);
    }

    public function testAnIdentityCannotBeBuiltWithoutACodeOrACountry(): void
    {
        $certificate = TestPki::cardAuth()->certificate;

        try {
            new AuthenticatedIdentity('', 'JAAK-KRISTJAN', 'JOEORG', 'EE', $certificate, IdentifierType::PersonalNumber);
            self::fail('An identity without a code was built');
        } catch (InvalidArgumentException) {
        }

        $this->expectException(InvalidArgumentException::class);

        new AuthenticatedIdentity('38001085718', 'JAAK-KRISTJAN', 'JOEORG', 'Estonia', $certificate, IdentifierType::PersonalNumber);
    }

    public function testTheJsonCarriesTheIdentifierType(): void
    {
        $certificate = TestCertificates::issue(TestPki::cardAuth(), ['id-at-countryName' => 'EE', 'id-at-serialNumber' => 'PASEE-K1234567'])->certificate;

        $json = AuthenticatedIdentity::fromCertificate($certificate)->jsonSerialize();

        self::assertSame(AuthenticatedIdentity::VERSION, $json['version']);
        self::assertSame(2, $json['version']);
        self::assertSame('PAS', $json['identifierType']);
        self::assertSame('K1234567', $json['identityCode']);
        self::assertSame('EE', $json['country']);
    }
}
