# allkiri

Estonian eID for PHP: **authenticate** users and **create / validate qualified
digital signatures** with the ID-card family (via Web eID), Mobile-ID and
Smart-ID, plus local keys for e-seals and tests. Produces and validates ASiC-E
containers with XAdES-LT signatures, the format DigiDoc4 opens.

> **Status: alpha.** All four eID means work, signatures reach XAdES-LTA,
> production trust is taken from the European list of trusted lists, and there
> is a demo application that exercises the lot. Tested against the real Estonian
> test services. Four things stand between this and 1.0: the ID card on real
> hardware, a Smart-ID device link scanned by a person, the manual DigiDoc4
> checklist, and a smoke test against the production services. The API may still
> change until then.

## Why

PHP has only fragments: official *authentication-only* clients for Web eID,
Mobile-ID and Smart-ID, and no maintained equivalent of digidoc4j or
libdigidocpp for building the signature container. SK's own Mobile-ID PHP
client says it outright: signing is not supported because no such library
exists for PHP. `allkiri` is that library.

## What works today

```php
use Allkiri\Allkiri;
use Allkiri\Config\Environment;
use Allkiri\Container\AsicContainer;
use Allkiri\Container\DataFile;
use Allkiri\Crypto\PrivateKey;
use Allkiri\Signing\LocalKeySigner;

$allkiri = new Allkiri(Environment::demo());

$container = AsicContainer::create(DataFile::fromPath('leping.pdf'));
$keyPair = PrivateKey::fromPkcs12(file_get_contents('seal.p12'), $password);

$result = $allkiri->signingService()->signWith($container, LocalKeySigner::fromKeyPair($keyPair));
file_put_contents('leping.asice', $allkiri->writer()->write($result->container));

$report = $allkiri->validator()->validateFile('leping.asice');
```

- **Signing** with a local key or e-seal, at level B, T, LT or LTA, with ECDSA
  (P-256, P-384) or RSA (PKCS#1 or PSS).
- **Archive timestamps**, so a signature outlasts the algorithms it was made
  with. Applied at signing or years later, as many times as needed.
- **Mobile-ID**, for signing in and for signing, with the verification code,
  typed outcomes for everything SK publishes, and sessions that survive between
  two HTTP requests. See [docs/mobile-id.md](docs/mobile-id.md).
- **Smart-ID** v3, both flow families: push notifications, and device links for
  QR codes and taps. RSASSA-PSS signatures, which is what SK now requires. See
  [docs/smart-id.md](docs/smart-id.md).
- **The ID card**, through Web eID, for signing in and for signing, with the
  card's own algorithms negotiated rather than assumed. See
  [docs/web-eid.md](docs/web-eid.md).
- **A two-step API** built for remote signers: `prepare()` hands you a digest
  and a serialisable session, `finalize()` takes the value back. All four means
  use it unchanged.
- **Containers**: create, read, and append a signature without disturbing a
  byte of what was already signed.
- **Validation** with verdicts in the vocabulary SiVa and DigiDoc4 use, and an
  optional second opinion from SiVa itself.
- **Trust** from the European list of trusted lists, verified against the
  certificates the Official Journal publishes, or from any list you pin
  yourself.

- **A browser helper**, dependency-free, that drives the Web eID extension,
  shows verification codes and draws the QR code Smart-ID needs. It decides
  nothing: every answer goes to your server. See
  [docs/browser.md](docs/browser.md).

| Guide | |
|---|---|
| [docs/signing.md](docs/signing.md) | making a signature, and the two-step API |
| [docs/validation.md](docs/validation.md) | reading a verdict, and every finding code |
| [docs/mobile-id.md](docs/mobile-id.md) | Mobile-ID |
| [docs/smart-id.md](docs/smart-id.md) | Smart-ID, both flow families |
| [docs/web-eid.md](docs/web-eid.md) | the ID card |
| [docs/browser.md](docs/browser.md) | the page: `assets/allkiri.js` |
| [docs/frameworks.md](docs/frameworks.md) | wiring it into Laravel or Symfony |
| [docs/logging.md](docs/logging.md) | the audit trail, and what must never reach a log |
| [docs/trust.md](docs/trust.md) | trusted lists, and what production needs |

## Try it

```bash
composer install
php -S localhost:8080 -t examples/demo-app/public
```

A small application that signs in with Mobile-ID, Smart-ID or an ID card, signs
an upload with any of them, archives the result and validates a container. It
runs against the free test services with published test credentials, so nothing
real is involved. See [examples/demo-app/README.md](examples/demo-app/README.md).

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 0 | Repository bootstrap: tooling, CI, docs | done |
| 1 | Signing core: ASiC-E, XAdES-LT, local-key signer, trust store, native validator | done |
| 2 | Mobile-ID: authentication and signing | done |
| 3 | Smart-ID v3: authentication and signing, device-link flows | done |
| 4 | Web eID: authentication and signing, production trust lists | done |
| 5 | XAdES-LTA, validation polish | done |
| 6 | Browser helper, demo app, framework guides | done |
| — | Hardware and production gates, then 1.0 on Packagist | remaining |

## What it is measured against

Not our own tests alone:

- Containers made by **digidoc4j** (ECDSA P-256 and P-384, RSA, LT, LTA, two
  signatures) verify with our own code, and one validates TOTAL-PASSED end to
  end once its PKI is trusted.
- The **Estonian test trusted list** and the test list of lists verify against
  the certificate RIA publishes.
- Real responses captured from **SK's demo** timestamp and OCSP services parse
  and verify.
- Nightly, against the live demo services: a timestamp is obtained and chained
  to the trusted list, a real test ID-card certificate's revocation status is
  fetched through the responder its own certificate names, and **SiVa** is
  asked to judge what we produce.
- **SK's published Mobile-ID demo numbers**, every one of them: each documented
  failure arrives as its own typed result, and containers signed by the ECC and
  the RSA demo number are TOTAL-PASSED in SiVa.
- **SK's published Smart-ID demo accounts**: authentication by account and by
  person, every documented refusal, a certificate choice, and RSA-PSS containers
  that are TOTAL-PASSED in SiVa.
- **The live European list of trusted lists**: its signature verifies against
  the certificates the Official Journal publishes, and the Estonian authorities
  behind every eID mean here are reached through it. Latvian and Lithuanian
  lists are reachable the same way.
- **An archive timestamp digidoc4j made**: our computation of what it covers
  digests to exactly the imprint its timestamp authority was asked to stamp, and
  a container we archive is read as XAdES_BASELINE_LTA by SiVa.

Both Estonian card PKIs are handled: IDEMIA cards (SK ID Solutions) and the
Thales cards issued since November 2025 (Zetes).

## Requirements

PHP 8.2 or newer with `curl`, `dom`, `mbstring`, `openssl` and `zlib`.

No `zip` extension: the ASiC-E container layer is written here, because
`ZipArchive` cannot be made to emit the uncompressed first entry the format
requires. Running the test suite does need it, for cross-checking what our own
writer produced.

Framework-agnostic: bring your own PSR-18 HTTP client, PSR-3 logger and PSR-16
cache, or use the built-in ones. The library never touches sessions, files or
databases on its own.

## Development

```bash
composer install
composer check              # coding standard + static analysis + unit tests
composer test:integration   # needs ALLKIRI_INTEGRATION=1, talks to demo services
```

The unit suite runs entirely offline: an in-process timestamp authority and
OCSP responder stand in for the real ones, so a full XAdES-LT signature is
built and verified without a network or eID hardware. See
[docs/testing.md](docs/testing.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## Specifications

Every specification, endpoint and reference implementation this is built
against is listed in [docs/specs.md](docs/specs.md). Decisions that cost an
afternoon to establish are recorded in [docs/decisions.md](docs/decisions.md).
What stands between this and 1.0, and what the version number covers, are in
[docs/releasing.md](docs/releasing.md).

## License

[MIT](LICENSE).
