# allkiri

Estonian eID for PHP: **authenticate** users and **create / validate qualified
digital signatures** with the ID-card family (via Web eID), Mobile-ID and
Smart-ID, plus local keys for e-seals and tests. Produces and validates ASiC-E
containers with XAdES-LT and XAdES-LTA signatures, the format DigiDoc4 opens.

> **Status: pre-alpha. Nothing is usable yet.** The repository is being built
> phase by phase (table below). Do not depend on it before 1.0.

## Why

PHP has only fragments: official *authentication-only* clients for Web eID,
Mobile-ID and Smart-ID, and no maintained equivalent of digidoc4j or
libdigidocpp for building the signature container. SK's own Mobile-ID PHP
client says it outright: signing is not supported because no such library
exists for PHP. `allkiri` is that library.

## What it will do

| Area | ID-card (Web eID) | Mobile-ID | Smart-ID (RP API v3) | Local key |
|---|---|---|---|---|
| Authentication | yes | yes | yes, device-link and notification flows | n/a |
| Signing | yes | yes | yes, RSASSA-PSS | yes |
| Container | ASiC-E, new or append to existing | same | same | same |
| Signature level | XAdES-LT, optionally LTA | same | same | same |
| Validation | native validator, optional SiVa second opinion | | | |

Both Estonian card PKIs are supported: IDEMIA cards (SK ID Solutions) and the
Thales cards issued since November 2025 (Zetes).

Framework-agnostic: PSR-18 HTTP client, PSR-3 logger, PSR-16 cache. The
library never touches sessions, files or databases on its own; every remote
signing flow hands you a serialisable state object you store between requests.

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 0 | Repository bootstrap: tooling, CI, docs | done |
| 1 | Signing core: ASiC-E, XAdES-LT, local-key signer, trust store, native validator | planned |
| 2 | Mobile-ID: authentication and signing | planned |
| 3 | Smart-ID v3: authentication and signing, device-link flows | planned |
| 4 | Web eID: authentication and signing, production trust lists | planned |
| 5 | XAdES-LTA, validation polish, SiVa adapter | planned |
| 6 | Browser helper, demo app, docs, 1.0 on Packagist | planned |

Every phase is verified against the public demo environments of SK ID
Solutions, RIA and Zetes, and cross-checked with SiVa and DigiDoc4. See
[docs/specs.md](docs/specs.md) for every specification and endpoint this
library is built against.

## Requirements

PHP 8.2 or newer with `curl`, `dom`, `mbstring`, `openssl` and `zip`.

## Development

```bash
composer install
composer check              # coding standard + static analysis + unit tests
composer test:integration   # needs ALLKIRI_INTEGRATION=1, talks to demo environments
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE).
