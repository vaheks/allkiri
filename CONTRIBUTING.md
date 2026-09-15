# Contributing

## Setup

```bash
composer install
composer check
```

`composer check` runs exactly what CI runs: php-cs-fixer (dry run), PHPStan at
level max, and the Unit test suite. Fix style with `composer cs:fix`.

## Conventions

- PHP 8.2 is the floor; CI also runs 8.3 and 8.4. Use `declare(strict_types=1)`.
- Coding standard: PER-CS 2.0 via php-cs-fixer, see `.php-cs-fixer.dist.php`.
- Static analysis: PHPStan level max with strict rules. No baseline; fix or
  narrow types instead.
- Namespaces mirror `src/` (`Allkiri\Xades\...`). The parts of the library
  form one graph without cycles. From the bottom up:

  1. `Exception`, `Clock`
  2. `Resources`, `Http`
  3. `Crypto`
  4. `StoredData`, `Auth`, `Xml`
  5. `Container`, `Trust`
  6. `Xades`, `Config`
  7. `Signing`
  8. `Validation`, `MobileId`, `SmartId`, `WebEid`
  9. the `Allkiri` facade

  A part refers only to parts on lower levels, though not to all of them.
  `tests/Unit/NamespaceLayeringTest.php` holds the exact table of which part
  uses which, and fails on any reference outside it, an Allkiri class named in
  a comment included. A new dependency goes into that table first, where a
  cycle shows at once.
- Every exception implements `Allkiri\Exception\AllkiriException`. A programmer
  or configuration error throws `Allkiri\Exception\InvalidArgumentException`;
  everything else extends `\RuntimeException` through its module's base class.
  Never throw an SPL exception or an anonymous exception class.
- Never hardcode an OCSP responder. Take it from the certificate's AIA
  extension and allow an override map.
- Everything a caller must persist between HTTP requests is a plain,
  JSON-serialisable DTO.

## Tests

- `tests/Unit` must run offline and deterministically. Captured responses
  (OCSP, timestamps, TSLs, signed containers) live under `tests/fixtures`.
- `tests/Integration` extends `IntegrationTestCase` and self-skips unless
  `ALLKIRI_INTEGRATION=1`. It uses the public demo environments and the
  public `DEMO` relying-party credentials by default:

  | Variable | Default |
  |---|---|
  | `ALLKIRI_MID_RP_UUID` | `00000000-0000-0000-0000-000000000000` |
  | `ALLKIRI_MID_RP_NAME` | `DEMO` |
  | `ALLKIRI_SMARTID_RP_UUID` | `00000000-0000-4000-8000-000000000000` |
  | `ALLKIRI_SMARTID_RP_NAME` | `DEMO` |

- Signed containers produced in tests should be validated with SiVa demo
  (`https://siva-demo.eesti.ee/V3/validate`) in the integration suite and
  opened in DigiDoc4 (test mode) whenever a signature format changes.

## Fixtures and secrets

- Only test certificates and demo-environment data may be committed. Never
  commit a container signed with a real person's certificate, a production
  relying-party UUID, or a private key that is not a throwaway test key.
- Binary fixtures are listed in `.gitattributes` so Git never rewrites them.

## Pull requests

One topic per PR, tests included, CI green. Describe what was verified
against which environment (unit only, demo environments, DigiDoc4, SiVa).
