# Releasing

## What 1.0 waits for

Everything in the library is written and tested against the free Estonian test
services. Four things remain, and none of them can be done by software alone.

| # | Gate | What it needs |
|---|---|---|
| 1 | The ID card on real hardware | an IDEMIA test card, a Thales test card, a reader and a person. Items 12 to 15 of [manual-testing.md](manual-testing.md), through `examples/demo-app` over HTTPS, which [its README](../examples/demo-app/README.md#running-it) shows how to set up |
| 2 | A Smart-ID device link scanned | a phone with the Smart-ID demo app and a demo account, scanning the code that "Smart-ID without an identity code" draws in `examples/demo-app`. SK's mock scan already completes that sign-in (see [smart-id.md](smart-id.md#testing)); the gate is a real app reading the code off a screen |
| 3 | The DigiDoc4 checklist | DigiDoc4 beta, pointed at the test trusted list. All sixteen items of [manual-testing.md](manual-testing.md) |
| 4 | A production smoke test | contracts with SK for Mobile-ID, Smart-ID and the timestamp service, and a machine whose public address SK has registered for them; revocation needs no contract ([going-live.md](going-live.md)). `composer test:live`, then open what it writes in DigiDoc4's default mode |

Gate 4 is the only one that costs money, and it is the one that matters most:
production uses different endpoints, different relying-party credentials, a
different trusted list and a timestamp service on a paid monthly plan. Nothing
in the test environment proves any of that works.

Run it like this, from a machine whose address SK has registered:

```bash
cp .env.example .env      # fill in the five live values, plus your own phone and codes
ALLKIRI_LIVE_SMOKE=1 ALLKIRI_ARTEFACTS=/some/directory composer test:live
```

It signs once with Mobile-ID and once with Smart-ID, prints each verification
code, validates both containers with our own validator and with SiVa production,
and writes them out for DigiDoc4. Two phone interactions are needed for Smart-ID:
signing addresses a device rather than a person, and learning which device costs
an authentication.

Nothing scheduled can reach it. It lives in its own test suite, which neither
`composer test` nor `composer test:integration` loads, and it refuses to run
unless `ALLKIRI_LIVE_SMOKE=1` and `ALLKIRI_MODE=live` are both set.

Until all four are recorded as done, the README says alpha and the version stays
below 1.0.

## Releasing, once the gates are met

```bash
# 1. The checklist is filled in, with dates and results.
$EDITOR docs/manual-testing.md

# 2. Unreleased becomes the version, with today's date, under a new empty
#    Unreleased. Point the Unreleased link at the new tag, and add a compare
#    link for the version.
$EDITOR CHANGELOG.md

# 3. The status paragraph loses the word alpha, and the install line its
#    @alpha.
$EDITOR README.md

# 4. Everything is green.
composer check && composer test:js
gh workflow run integration.yml

# 5. Tag it. Tags carry no "v", like the ones before.
git commit -am "release: 1.0.0" && git push
git tag -s 1.0.0 -m "1.0.0" && git push origin 1.0.0
```

Sign the tag. Packagist resolves a version to whatever the tag points at, so
the tag is what stands between this repository and everyone's `composer
install`. `git tag -s` needs a signing key GitHub knows about; with an SSH key,
`git config --global gpg.format ssh` and `git config --global user.signingkey
~/.ssh/id_ed25519.pub`, and the same public key added to GitHub under Settings,
SSH and GPG keys, as a **signing** key rather than an authentication one.
GitHub then shows the tag as Verified.

Nothing in the code is bumped. The User-Agent sent to SK, RIA and Zetes reads
the version from Composer, which takes it from the tag an application installs.

Packagist publishes the tag through the GitHub hook, which has been in place
since the repository went public.

## Before 1.0

Releases before 1.0 are alphas, tagged like `0.7.0-alpha.1`, and an application
installs one with `composer require vaheks/allkiri:^0.7@alpha`, as the README
says. The package has been on
[Packagist](https://packagist.org/packages/vaheks/allkiri) since the repository
went public on 2026-09-17, and the GitHub hook publishes every tag, alpha or
not. When an alpha moves past the range the README's install line names, the
line moves with it.

An alpha waits for no gates, only for the same care:

1. Unreleased becomes the version in `CHANGELOG.md`, as in step 2 above.
2. `composer check && composer test:js` pass, and CI is green on the commit.
3. `git tag -a <version> -m "…"` with a title line, what the release brings and
   what is still alpha, like the tags before it. Then push the tag.
4. If the version left the README's install range, the install line follows.

## When something is found

The repository is public, so filing an issue is publishing. Anything that could
be used against an application running this library goes in a **draft security
advisory** instead (Security, Advisories, New draft), which comes with a private
fork to fix it in. Publish the advisory with the release that carries the fix,
and put the entry under `### Security` in the changelog, naming the versions it
affects. Hardening with no way to exploit it is an ordinary issue.

Reports from outside arrive the same way; `SECURITY.md` is what tells people so.

## The nightly integration run

`integration.yml` is the watch on the outside world: it notices when the
Commission rotates the certificates that sign the European list of trusted
lists, and when a demo service changes under us. Two things to know about it.

It is scheduled, and **GitHub disables a scheduled workflow after 60 days with
no activity in the repository**, without much of a notice. A quiet period is
exactly when nobody is watching, so check that it still runs after one.

It has no failure handling of its own: a failed run is an email to whoever last
touched the cron, and nothing else. If that stops being enough, give it a step
that opens an issue — but keep the response bodies out of it, since they carry
identity codes from the demo accounts.

## Versioning

Semantic versioning, with one clarification worth stating because this library
sits in front of other people's legal obligations:

**A validation verdict changing is not a breaking change.** Trusted lists
change, certificates expire, algorithms weaken, and a container that validated
last year may not this year. That is the system working.

## What the version number covers

**Everything in `Allkiri\` that is not marked `@internal`:** every class,
interface, enum, constant, method and property a caller can reach. Removing
one, changing its signature or changing what it does needs a major release;
adding one needs a minor release. The entry points, by area:

| Area | Entry points |
|---|---|
| Facade | `Allkiri` |
| Configuration | `Config\Environment`, `Config\ArrayCache` |
| Containers | `Container\AsicReader`, `AsicWriter`, `AsicContainer`, `DataFile`, `SignatureFile`, `Manifest` |
| Signing | `Signing\SigningService`, `SigningOptions`, `SignatureLevel`, `DataToBeSigned`, `SigningResult`, `Signer`, `LocalKeySigner`, `LtExtender`, `LtaExtender`, and `Xades\SignatureProfile` |
| Validation | `Validation\ContainerValidator`, `SignatureValidator`, `ValidationOptions`, `ValidationPolicy`, `FindingCodes`, the classes in `Report`, and the SiVa client in `Siva` |
| Trust | `Trust\ChainBuilder`, `CertificateChain`, the `TrustStore` implementations, `TrustAnchor`, `ServiceType`, `ServiceStatus`, and in `TrustedList` the loader, the sources and what they load |
| Mobile-ID, Smart-ID, Web eID | `Auth\AuthenticatedIdentity`; in `MobileId`, `SmartId` and `WebEid` the authenticators, signers, clients, configurations, sessions and the values they take and return |
| Crypto | `Crypto\Certificate`, `PrivateKey`, `KeyPair`, the algorithm and key types, `AlgorithmConstraints`, the OCSP and timestamp clients, and the parsed OCSP responses, timestamp tokens and CMS structures they return |
| HTTP | `Http\HttpClient`, `CurlHttpClient`, `Psr18HttpClient`, `LoggingHttpClient`, `HttpRequest`, `HttpResponse`, `UserAgent` |
| Time | `Clock\SystemClock`, `Sleeper`, `SystemSleeper` |
| Exceptions | every one; all of them implement `Exception\AllkiriException` |

**Stored JSON.** An application keeps these between two requests, or longer,
so a later minor release reads what an earlier one wrote:

- the seven sessions and prepared signatures an application restores:
  `DataToBeSigned`, `WebEidChallenge`, `WebEidSigningSession`,
  `MobileIdSession`, `MobileIdSigningSession`, `SmartIdSession` and
  `SmartIdSigningSession`. Each carries a `version`. A new shape takes a new
  version, and `fromJson()` keeps reading the older ones until the next major
  release, as `SmartIdSession` reads version 1;
- the JSON of a `ValidationReport`;
- the JSON of an `AuthenticatedIdentity`, which carries a `version` of its own.

A key may be added to the report or the identity in a minor release; removing
or renaming one, or changing what its value means, is major.

**Finding codes.** The codes in `FindingCodes` are covered so that an
application can branch on them. Adding one is a minor release; changing what an
existing one means is major.

**Not covered:**

- anything marked `@internal`: the ASN.1, ZIP and XML machinery, XML-DSig
  verification, the XAdES build and parse classes, building and verifying OCSP
  and timestamp requests, the trusted-list parser and verifier, the Smart-ID
  payload and status parser, and the members of covered classes that take or
  return them. `tests/Unit/PublicApiTest.php` lists the classes;
- an optional constructor parameter that takes an internal class. Those exist
  so that tests can swap a collaborator, and come after every covered
  parameter;
- the wording of exception messages, finding messages and log lines. Branch on
  the exception class, its reason where it has one, and the finding code;
- validation verdicts, for the reason above.

## Adding a constructor parameter

After 1.0, a covered parameter cannot be added in the middle of a constructor,
however much it belongs there. `SigningService` gained `$ltaExtender` next to
`$ltExtender` during Phase 5 and every positional caller silently passed the
wrong argument; PHPStan caught it only because the types differed. Add it after
the last covered parameter, before any internal collaborators, or introduce a
new named constructor.
