<?php

declare(strict_types=1);

/*
 * Writes the JSON every stored type serialises to, one file each, into this
 * directory. Run it from the root of a checkout of the release whose JSON is
 * to be kept:
 *
 *     git worktree add ../allkiri-0.8 0.8.0-alpha.1
 *     cd ../allkiri-0.8 && composer install
 *     php /path/to/this/generate.php
 *
 * It writes into the directory it is in, so run the copy in this repository
 * against the older checkout's code by passing that checkout as the argument:
 *
 *     php tests/fixtures/stored/generate.php ../allkiri-0.8
 *
 * The files it wrote from 0.8.0-alpha.1 are committed, and StoredJsonTest
 * restores each with today's code. Nothing here is real: the people, keys and
 * services are the test suite's own.
 */

use Allkiri\Auth\AuthenticatedIdentity;
use Allkiri\Container\AsicContainer;
use Allkiri\Container\DataFile;
use Allkiri\Crypto\Ocsp\OcspClient;
use Allkiri\MobileId\MobileIdAuthenticator;
use Allkiri\MobileId\MobileIdClient;
use Allkiri\MobileId\MobileIdIdentity;
use Allkiri\MobileId\MobileIdSigner;
use Allkiri\Signing\SignatureLevel;
use Allkiri\Signing\SigningOptions;
use Allkiri\SmartId\DocumentNumber;
use Allkiri\SmartId\Interactions;
use Allkiri\SmartId\SmartIdAuthenticator;
use Allkiri\SmartId\SmartIdClient;
use Allkiri\SmartId\SmartIdSigner;
use Allkiri\Tests\Support\MobileId\MockMobileIdService;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Tests\Support\SigningFixture;
use Allkiri\Tests\Support\SmartId\MockSmartIdService;
use Allkiri\Validation\ContainerValidator;
use Allkiri\Validation\SignatureValidator;
use Allkiri\WebEid\WebEidChallenge;
use Allkiri\WebEid\WebEidSigner;

$checkout = rtrim($argv[1] ?? (string) getcwd(), '/\\');
require $checkout . '/vendor/autoload.php';

$fixture = new SigningFixture();
$container = AsicContainer::create(DataFile::fromString('leping.txt', "Tere, allkiri!\n"));
$documentNumber = new DocumentNumber(MockSmartIdService::DOCUMENT_NUMBER);
$interactions = Interactions::forText('Log in to the allkiri tests', 'Log in');
$written = [];

$written['data-to-be-signed'] = $fixture->signingService->prepare($container, TestPki::signerEc256()->certificate, new SigningOptions(SignatureLevel::LT));

$written['web-eid-challenge'] = new WebEidChallenge(
    base64_encode(str_repeat("\x2a", 32)),
    new DateTimeImmutable('2026-03-01T10:00:00+00:00'),
    new DateTimeImmutable('2026-03-01T10:05:00+00:00'),
);
$written['web-eid-signing-session'] = (new WebEidSigner($fixture->signingService))->prepare(
    $container,
    TestPki::signerEc384()->certificate->base64(),
    [['cryptoAlgorithm' => 'ECC', 'hashFunction' => 'SHA-384', 'paddingScheme' => 'NONE']],
);

$mobileId = MockMobileIdService::register($fixture->http);
$mobileIdClient = new MobileIdClient($mobileId->configuration(), $fixture->http);
$person = new MobileIdIdentity('+37200000766', '60001019906');
$written['mobile-id-session'] = (new MobileIdAuthenticator($mobileIdClient, $fixture->chainBuilder))->start($person);
$written['mobile-id-signing-session'] = (new MobileIdSigner($mobileIdClient, $fixture->signingService))->start($container, $person);

$smartId = MockSmartIdService::register($fixture->http);
$smartIdClient = new SmartIdClient($smartId->configuration(), $fixture->http);
$written['smart-id-session'] = (new SmartIdAuthenticator($smartIdClient, $fixture->chainBuilder, new OcspClient($fixture->http, $fixture->clock)))
    ->startNotification($documentNumber, $interactions);
$written['smart-id-signing-session'] = (new SmartIdSigner($smartIdClient, $fixture->signingService))
    ->startNotification($container, $documentNumber, $interactions);

$written['authenticated-identity'] = AuthenticatedIdentity::fromCertificate(TestPki::signerRsaPerson()->certificate);

$signed = $fixture->signingService->signWith($container, Allkiri\Signing\LocalKeySigner::fromKeyPair(TestPki::signerEc256()));
$validator = new ContainerValidator(new SignatureValidator($fixture->trustStore), $fixture->clock);
$written['validation-report'] = $validator->validate((new Allkiri\Container\AsicWriter())->write($signed->container), 'leping.asice');

foreach ($written as $name => $value) {
    $json = json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    file_put_contents(__DIR__ . '/' . $name . '.json', $json . "\n");
    echo $name, "\n";
}
