# allkiri

Estonian eID for PHP. Sign people in with an ID card, Mobile-ID or Smart-ID,
have them sign documents, and check the signatures you receive. The documents
are ASiC-E containers with XAdES signatures, the files DigiDoc4 opens.

> **Status: alpha.** Every means has signed people in and signed documents
> against the production services, by hand, in September 2026, including a
> Smart-ID QR code and the Smart-ID app on the same phone. Before 1.0 the manual
> checklist and the production smoke test still have to be run and recorded
> ([releasing.md](docs/releasing.md)). The API may change until then.

## Why

PHP has only fragments: official *authentication-only* clients for Web eID,
Mobile-ID and Smart-ID, and no maintained equivalent of digidoc4j or
libdigidocpp for building the signature container. SK's own Mobile-ID PHP
client says it outright: signing is not supported because no such library
exists for PHP. `allkiri` is that library.

## Install

```bash
composer require vaheks/allkiri:^0.6@alpha
```

Until 1.0 every release is an alpha, and Composer installs one only when asked,
which is what `@alpha` does. The PHP version and extensions it needs are under
[Requirements](#requirements).

## Quick start

Everything below runs against SK's free test services with their published
test accounts. [Going live](#going-live) says what production needs instead.

### Sign someone in with Mobile-ID

Two requests: one sends the request to the phone, the page then polls the
other until the person answers.

```php
use Allkiri\Allkiri;
use Allkiri\Config\Environment;
use Allkiri\MobileId\MobileIdConfiguration;
use Allkiri\MobileId\MobileIdIdentity;
use Allkiri\MobileId\MobileIdSession;

$allkiri = new Allkiri(Environment::demo());
$authenticator = $allkiri->mobileIdAuthenticator(MobileIdConfiguration::demo());

// First request: show the code before the person reaches for their phone.
$session = $authenticator->start(new MobileIdIdentity('+37200000766', '60001019906'));
echo $session->verificationCode;
$_SESSION['mid'] = json_encode($session);

// Polled from the page: null until they answer.
$identity = $authenticator->poll(MobileIdSession::fromJson($_SESSION['mid']));
echo $identity?->semanticsIdentifier();   // "PNOEE-60001019906", the account key
```

Smart-ID works the same way, by identity code, by QR code, or by opening the
Smart-ID app on the same phone. The ID card signs in through the browser with
Web eID.

### Have them sign a document with Smart-ID

```php
use Allkiri\Container\AsicContainer;
use Allkiri\Container\DataFile;
use Allkiri\SmartId\DocumentNumber;
use Allkiri\SmartId\Interactions;
use Allkiri\SmartId\SmartIdConfiguration;

$signer = $allkiri->smartIdSigner(SmartIdConfiguration::demo());
$container = AsicContainer::create(DataFile::fromPath('leping.pdf'));

// First request. The document number names the person's Smart-ID account;
// keep the one they signed in with, or ask their phone for it.
$signing = $signer->startNotification($container, new DocumentNumber($documentNumber), Interactions::forText('Sign the lease'));
echo $signing->verificationCode();

// Polled from the page, with the same container: null until they answer.
$result = $signer->poll($container, $signing);
if ($result !== null) {
    file_put_contents('leping.asice', $allkiri->writer()->write($result->container));
}
```

The signature is timestamped and carries its revocation answer, so it is
XAdES-LT, which DigiDoc4 and SiVa accept. Mobile-ID and the ID card sign the
same way.

### Check a signed document

```php
$report = $allkiri->validator()->validateFile('leping.asice');

foreach ($report->signatures as $signature) {
    echo $signature->signedBy(), ': ', $signature->indication->value, "\n";   // "TOTAL-PASSED"
}
```

## Going live

allkiri is free. Some of the services behind it are not:

| You want to | You need |
|---|---|
| Sign people in with an ID card | nothing but HTTPS |
| Sign people in with Mobile-ID or Smart-ID | a contract with SK for each, and your server's address registered with SK |
| Have people sign documents | the above for the means you offer, plus SK's timestamping service |
| Check documents you receive | nothing |

Revocation checks and the trusted lists are free. [docs/going-live.md](docs/going-live.md)
covers each service, what it costs, what your server needs, and what to check
before the first real person signs.

## What it does

- **Signing in** with the ID card (Web eID), Mobile-ID and Smart-ID, with the
  verification code, typed outcomes for everything SK publishes, and sessions
  that survive between two HTTP requests.
- **Smart-ID v3** in full: push notifications, QR codes, and the app on the
  same device with its callback checked. RSASSA-PSS, as SK now requires.
- **Signing** with any of the three, or with a local key or e-seal, at level B,
  T, LT or LTA, with ECDSA (P-256, P-384) or RSA (PKCS#1 or PSS). The card's own
  algorithm is negotiated rather than assumed.
- **A two-step API** for remote signers: `prepare()` hands you a digest and a
  serialisable session, `finalize()` takes the value back.
- **Containers**: create, read, and add a signature without disturbing a byte
  of what was already signed.
- **Archive timestamps**, so a signature outlasts the algorithms it was made
  with, applied at signing or years later.
- **Validation** with verdicts in the vocabulary SiVa and DigiDoc4 use, and an
  optional second opinion from SiVa itself.
- **Trust** from the European list of trusted lists, verified against the
  certificates the Official Journal publishes and following the Commission's
  changes of them, or from any list you pin yourself.
- **A browser helper**, dependency-free, that drives the Web eID extension,
  shows verification codes and draws the Smart-ID QR code. It decides nothing:
  every answer goes to your server.

Both Estonian card PKIs are handled: IDEMIA cards (SK ID Solutions) and the
Thales cards issued since November 2025 (Zetes).

| Guide | |
|---|---|
| [docs/going-live.md](docs/going-live.md) | the services, contracts and costs production needs |
| [docs/signing.md](docs/signing.md) | making a signature, and the two-step API |
| [docs/validation.md](docs/validation.md) | reading a verdict, and every finding code |
| [docs/mobile-id.md](docs/mobile-id.md) | Mobile-ID |
| [docs/smart-id.md](docs/smart-id.md) | Smart-ID, every flow |
| [docs/web-eid.md](docs/web-eid.md) | the ID card |
| [docs/browser.md](docs/browser.md) | the page: `assets/allkiri.js` |
| [docs/frameworks.md](docs/frameworks.md) | wiring it into Laravel or Symfony |
| [docs/logging.md](docs/logging.md) | the audit trail, and what must never reach a log |
| [docs/trust.md](docs/trust.md) | trusted lists, and what production trusts |

## Try the demo

```bash
composer install
php -S localhost:8080 -t examples/demo-app/public examples/demo-app/public/index.php
```

A small application that signs in with any of the three means, signs uploaded
files with any of them, archives the result and validates a container. It runs
against the free test services, so nothing real is involved, or in live mode
against production with your own credentials. See
[examples/demo-app/README.md](examples/demo-app/README.md), which also shows how
to put HTTPS in front of it: the ID card works only over HTTPS.

## How it is tested

Not against its own tests alone:

- **digidoc4j's containers** (ECDSA P-256 and P-384, RSA, LT, LTA, two
  signatures) verify with our code, and **SiVa** judges what we produce.
- **SK's demo services**, nightly: every published Mobile-ID test number and
  Smart-ID demo account, every documented refusal, QR codes finished by SK's
  mock scan, and containers that SiVa reports TOTAL-PASSED.
- **The live European list of trusted lists**, nightly: its signature, the
  pivot lists that change its signers, and the Estonian authorities behind
  every means.
- **Captured responses** from SK's timestamp and OCSP services, and an archive
  timestamp digidoc4j made, whose coverage we reproduce to the byte.
- **Production**, by hand, with real cards and phones.

The unit suite runs offline: an in-process timestamp authority and OCSP
responder stand in for the real ones. See [docs/testing.md](docs/testing.md).

## Requirements

PHP 8.2 or newer with `curl`, `dom`, `mbstring`, `openssl` and `zlib`.
`intl` is optional: a Web eID site whose domain name is not ASCII needs it, or
its origin configured in Punycode.

No `zip` extension: the container layer reads and writes ZIP itself, because a
validator has to see what `ZipArchive` does not show, and adding a signature
has to leave the entries already there byte for byte. Running the test suite
does need it, to cross-check what our own writer produced.

Framework-agnostic: bring your own PSR-18 HTTP client, PSR-3 logger and PSR-16
cache, or use the built-in ones. The library never touches sessions, files or
databases on its own.

## Development

```bash
composer install
composer check              # coding standard + static analysis + unit tests
composer test:integration   # needs ALLKIRI_INTEGRATION=1, talks to demo services
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Every specification, endpoint and
reference implementation this is built against is listed in
[docs/specs.md](docs/specs.md), and decisions that took some establishing are
recorded in [docs/decisions.md](docs/decisions.md).

## Security

Report a vulnerability privately, as [SECURITY.md](SECURITY.md) describes, not
in a public issue.

## License

[MIT](LICENSE).
