# Releasing

## What 1.0 waits for

Everything in the library is written and tested against the free Estonian test
services. Four things remain, and none of them can be done by software alone.

| # | Gate | What it needs |
|---|---|---|
| 1 | The ID card on real hardware | an IDEMIA test card, a Thales test card, a reader and a person. Items 12 to 15 of [manual-testing.md](manual-testing.md), through `examples/demo-app` over HTTPS |
| 2 | A Smart-ID device link scanned | a phone with the Smart-ID demo app, scanning a QR code the demo application draws |
| 3 | The DigiDoc4 checklist | DigiDoc4 beta, pointed at the test trusted list. All sixteen items of [manual-testing.md](manual-testing.md) |
| 4 | A production smoke test | contracts with SK for Mobile-ID, Smart-ID, the timestamp service and OCSP. One real signature by each mean, validated in SiVa production and in DigiDoc4's default mode |

Gate 4 is the only one that costs money, and it is the one that matters most:
production uses different endpoints, different relying-party credentials, a
different trusted list and a timestamp authority that bills per stamp. Nothing
in the test environment proves any of that works.

Until all four are recorded as done, the README says alpha and the version stays
below 1.0.

## Releasing, once the gates are met

```bash
# 1. The checklist is filled in, with dates and results.
$EDITOR docs/manual-testing.md

# 2. Unreleased becomes the version, with today's date.
$EDITOR CHANGELOG.md

# 3. The status paragraph loses the word alpha.
$EDITOR README.md

# 4. Everything is green.
composer check && node tests/js/qr-golden.mjs
gh workflow run integration.yml

# 5. Tag it.
git commit -am "release: 1.0.0" && git push
git tag -a v1.0.0 -m "1.0.0" && git push origin v1.0.0
```

Then submit `https://github.com/vaheks/allkiri` at
<https://packagist.org/packages/submit> and enable the GitHub hook, so later
tags publish themselves.

## Versioning

Semantic versioning, with one clarification worth stating because this library
sits in front of other people's legal obligations:

**A validation verdict changing is not a breaking change.** Trusted lists
change, certificates expire, algorithms weaken, and a container that validated
last year may not this year. That is the system working. What is breaking is a
change to the API, to the finding codes, or to the serialised shape of a session
that an application stores between two HTTP requests.

The finding codes in `FindingCodes` are part of the public API precisely so that
an application can branch on them. Adding one is a minor release; changing what
an existing one means is major.

## Adding a constructor parameter

After 1.0, a parameter cannot be added in the middle of a constructor, however
much it belongs there. `SigningService` gained `$ltaExtender` next to
`$ltExtender` during Phase 5 and every positional caller silently passed the
wrong argument; PHPStan caught it only because the types differed. Add to the
end, or introduce a new named constructor.
