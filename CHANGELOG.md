# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

The signing core: everything needed to create and validate Estonian qualified
signatures with a local key, and the API the eID means will plug into.

- **Signing.** ASiC-E containers with XAdES-LT signatures, at level B, T or
  LT, with ECDSA (P-256, P-384) or RSA (PKCS#1 and PSS). The timestamp is
  taken before the revocation answer, as Estonian practice requires.
- **A two-step API.** `prepare()` returns a serialisable `DataToBeSigned`;
  `finalize()` takes the signature value back and verifies the whole signature
  against the container before spending anything on a timestamp or an OCSP
  request. Remote signers plug in without touching the container layer.
- **Containers.** Read, create and append. Appending copies the original ZIP
  entries byte for byte, so existing signatures stay valid.
- **Validation.** Verdicts in the ETSI vocabulary SiVa and DigiDoc4 report,
  with stable finding codes and a JSON-serialisable report. Optional second
  opinion from RIA's SiVa service.
- **Trust.** ETSI TS 119 612 trusted lists, verified against pinned signing
  certificates, with each service's status history so a signature made while a
  service was granted stays valid afterwards.
- **Crypto.** ASN.1, X.509, OCSP (RFC 6960), CMS SignedData and RFC 3161
  timestamps, all keeping the original DER so nothing is verified against a
  re-encoding of itself.
- **Configuration.** `Environment::demo()` works out of the box against the
  free Estonian test services; `Environment::production()` trusts nothing until
  the trusted list's signing certificates are pinned.
- **Mobile-ID.** Authentication and signing through SK's REST service, in the
  same two halves, with the four-digit verification code, long polling, and a
  typed result for every outcome SK publishes. Authentication signs a random
  challenge and the identity is believed only once that signature verifies
  against a valid, trusted certificate belonging to the person the session was
  started for. Display text is checked against what the chosen encoding can
  actually carry, because the service replaces anything else with spaces
  rather than refusing it.

- **Smart-ID v3.** Authentication and signing in both flow families:
  notifications pushed to a registered device, and device links for QR codes and
  taps, including an anonymous one that lets whoever scans identify themselves.
  Authentication verifies the ACSP_V2 payload, which binds an answer to one
  session on one service rather than merely to a challenge. Signing is
  RSASSA-PSS, which SK now requires, so the container declares an RFC 6931 PSS
  signature method and the parameters the service reports are checked against
  what that method describes rather than trusted. Device links carry an HMAC
  over the whole session, keyed with a secret that never leaves the server.

- **The ID card, through Web eID.** Authentication and signing. The card signs
  the site's origin together with the challenge and the token carries neither,
  so both are supplied from the server's own storage, which is what stops a
  token being relayed from another site or replayed against another session.
  The card chooses its own padding and only reports it afterwards, so the
  algorithm is negotiated from the list the card publishes and the answer is
  refused if it differs from what the signature was prepared for. The official
  validation library checks the token; trust and revocation use the same trust
  store, chain builder and OCSP client as everything else here.
- **Production trust from the European list of trusted lists.** The list of
  lists is verified against the certificates the Official Journal publishes,
  which are the only trust material shipped; it then says where a national list
  lives and which certificates may sign it. A national list can rotate its
  signing certificate without a release of this library.

- **Archive timestamps (XAdES-LTA).** An LT signature is only as good as the
  algorithms and certificates it rests on; an archive timestamp re-stamps the
  whole assembly so a fresh proof carries the old one, and can be laid over
  itself indefinitely. Made at signing time or, more usually, long afterwards
  through `SigningService::archive()`. The validator verifies them rather than
  noting their presence: what each covers, its own signature, its authority's
  trust, and its order relative to everything beneath it.
- **Report helpers.** `ReportRenderer` turns a validation report into lines a
  person can read, and `SivaComparison` names the differences between allkiri's
  verdict and SiVa's. Neither is part of any verdict.

- **The browser half.** `assets/allkiri.js` drives the Web eID extension,
  shows verification codes, and polls your own endpoints; it decides nothing,
  because a page cannot check a signature and must not pretend to.
  `assets/allkiri-qr.js` is a QR encoder, needed because a Smart-ID device link
  expires about once a second and only the server can mint the next one. Both
  are dependency-free and have no build step. The encoder is tested by pinning
  six known matrices and by encoding 1208 strings and reading every one of them
  back with an independent decoder.
- **A demo application.** `examples/demo-app`: sign in with all three eID means,
  turn an upload into a container, sign it with any of them, archive it, and
  validate anything. Plain PHP, no framework, one file of server code, written
  to be read rather than deployed.
- **Guides for the two halves nobody else documents.** `docs/browser.md` for
  the page, `docs/frameworks.md` for wiring it into Laravel or Symfony,
  including the session-lock trap that makes polling endpoints queue behind each
  other.

- **Two modes, and no way to confuse them.** `ALLKIRI_MODE` is one explicit word,
  `demo` or `live`. Live mode refuses to start unless all five credentials are
  present, names every missing one at once, and never falls back to the test
  services, because a signature made against those looks valid and is worth
  nothing. It also refuses the identifiers SK publishes, and demo mode refuses
  real ones. The demo page carries a banner saying which mode it is in, and
  prefills the published test numbers only in demo mode.
- **A production smoke test**, `composer test:live`: one real signature by
  Mobile-ID and one by Smart-ID, each validated by this library and by SiVa
  production. It lives in its own test suite, needs `ALLKIRI_LIVE_SMOKE=1` on
  top of live mode, and nothing scheduled sets either, because it signs with a
  real person's phone on services that bill per timestamp.

- **Logging, in two layers.** `LoggingHttpClient` wraps the client you give the
  library and records every remote call it makes, which is all four means plus
  timestamps, revocation checks and trusted lists. Credentials are never logged
  at any setting: the relying-party identifiers are shared secrets and a
  Smart-ID session secret mints device links for a whole session. Personal data
  is logged only when asked for, so by default no bodies are recorded and
  identity codes are removed from the URLs that carry them. The audit trail of
  who signed what stays the application's to write, because only it knows the
  business meaning, and `examples/demo-app` shows the ten lines that does it.
  See docs/logging.md.

- **A guard against containers that expand out of all proportion.** A few
  hundred kilobytes can declare hundreds of megabytes, which a validator taking
  uploads from strangers would dutifully hold. Reading now refuses that, with
  digidoc4j's own rule and defaults so the two libraries refuse the same
  archives: unquestioned up to a megabyte, and beyond it at most a hundred times
  the container's own size. Both numbers are configurable, the refusal has its
  own exception type, and a container that lies about its sizes is stopped part
  way through decompressing rather than after.
- **The ZIP writer refuses what the format cannot record**: more than 65535
  files, or any file or container of four gigabytes or more. Those go into
  32-bit and 16-bit fields, so previously they wrapped and produced a quietly
  corrupt archive. The reader already said so; now the writer does too.

### Changed

- `MobileIdAuthenticator` and `SmartIdAuthenticator` require a `ChainBuilder` as
  their second argument. It was optional, and without one the trust check was
  skipped. The `Allkiri` factory always passed one, so only code that constructs
  the authenticators directly has to change.
- `AuthenticatedIdentity` has a required `identifierType`, and its constructor
  refuses an empty identity code or a country that is not two letters.
  `semanticsIdentifier()` keeps the identifier's own type and country: a
  passport is `PASEE-…` or `PASFI-…`, never `PNOEE-…`. The JSON form is now
  version 2, with an `identifierType` field.
- A stored `SmartIdSession` is version 2 and keeps `initialCallbackUrl`.
  Version 1 sessions are still read, so a deploy does not end sessions in
  flight. `SmartIdSession::deviceLink()` no longer takes the callback URL; it
  uses the stored one for Web2App and App2App links and none for QR links. A
  Web2App or App2App answer now needs the callback's `userChallengeVerifier`
  in `poll()`.
- A stored `SmartIdSession` also keeps the certificate level it asked for and
  the person it was started for, as `certificateLevel` and
  `semanticsIdentifier`.

### Fixed

- Smart-ID sign-in now holds the answer to what the session asked for. Three
  things were wrong.
  - The certificate level came from the unsigned part of the answer and was
    compared with the configuration's level, not the call's. A call asking
    for QUALIFIED under an ADVANCED configuration accepted an ADVANCED answer,
    and a level nothing in the certificate bore out was believed.
  - A missing level was not refused.
  - The account that answered was never compared with the one asked for.

  The level a session asks for is now stored and enforced, and a missing level
  is refused. The certificate must carry the certificate policies of the level
  reported, as SK's own client requires. The document number, the person asked
  for and the certificate must all agree.

- Smart-ID sign-in through Web2App or App2App with a callback URL can succeed.
  The signed payload's tenth field is the callback URL for those flows, but
  allkiri always left it empty, and the session did not even keep the URL to
  put there. Every such sign-in completed on the phone and was then refused as
  "does not match this session". The unit tests agreed with the bug because the
  mock service built its payload with the same class. The payload is now checked
  against the worked example in SK's specification, digest included. A callback
  URL containing "|", which would shift the signed fields, is refused before
  Smart-ID is asked.

- The Mobile-ID and Smart-ID authenticators can no longer be built without a
  trust check. Constructed without a chain builder, as a dependency injection
  container easily does, they believed any certificate whose key had signed the
  challenge, including one from a test PKI or one the caller had issued, and
  said nothing. The class documentation and the Smart-ID guide promised the check
  unconditionally.

- A certificate that names no person no longer signs anyone in. An e-seal, or
  any certificate without a personal code, came back from Web eID sign-in with
  the identity code "" and the account key "PNOEE-", which every such
  certificate shared, and Smart-ID did not refuse it either. Organisation
  identifiers such as "NTREE-…" were read as personal codes, and a passport or
  identity card number was reported as a personal code, so "PASEE-123" and
  "PNOEE-123" became the same account. All three means now refuse a certificate
  that does not name a person by personal code, passport or identity card
  number. Mobile-ID, which is asked for by personal code, accepts only a
  personal code.

- A signature's signed properties can no longer be altered while the signature
  still verifies. A same-document reference was resolved to the first element
  carrying its `Id`, while the properties were read from inside the signature by
  position. An untouched copy placed beside the signature was therefore
  digested, and the altered original was reported: signing time, claimed roles,
  production place, media types and whether a policy identifier is present.
  Renaming the original worked just as well, with every `Id` unique. The
  properties are now read only from the element the reference resolves to. A
  reference whose `Id` more than one element carries fails with the new finding
  code `DUPLICATE_ID`, and one that resolves anywhere else fails with
  `SIGNED_PROPERTIES_REFERENCE_MISSING`. The signer's identity and the signed
  files were never at risk: the copy still commits to the real certificate, and
  data files are resolved by name.

- A DTD in a UTF-16 document is now refused. XML was checked for `<!DOCTYPE` by
  searching its bytes, and UTF-16 puts a zero byte between the characters, so
  such a document passed and libxml expanded its internal entities: a few bytes
  became a thousand in the reproduction, and a billion-laughs document would
  have grown as far as libxml2's own limits allow. Every signature file,
  manifest and trusted list is loaded this way. The parsed document is now
  checked as well. The entities are still expanded once, within those limits,
  before the document is refused. External entities were never loaded.

- A container holding two entries with one name is now refused. The reader kept
  the last one, so a tool that takes the first would show a different document
  under a signature reported as valid, and appending a signature carried both
  copies forward. libdigidocpp refuses the same archives. Also refused now:
  - an entry whose local header names it differently from the central
    directory, since a streaming reader sees that name instead;
  - an entry whose content does not match its CRC-32, which goes further than
    libdigidocpp or digidoc4j check.

  A manifest that lists one file twice is a failing finding, and the writer no
  longer produces two entries with one name.

- DER nested thousands of levels deep no longer takes a PHP process down.
  phpseclib's decoder copies each level's content, so its memory grows with the
  square of the depth. About 80 KB of nested SEQUENCEs exhausted a 128 MB limit,
  which is a fatal error rather than an exception. Such DER reached it from
  three places:
  - uploaded containers: embedded certificates, OCSP responses and timestamp
    tokens;
  - responses from the network;
  - anyone attempting an ID-card sign-in, whose certificate the Web eID
    validation library decodes before allkiri sees it.

  Nesting deeper than 64 levels is now refused before phpseclib is given the
  bytes. That includes certificate extension values and public keys, which
  phpseclib decodes a second time, so a certificate that looks shallow is
  refused too. The check follows phpseclib's own decoder step for step, so
  nothing it accepted before is refused for any other reason, except crafted
  input too intricate to walk within a budget proportional to its size. A test
  holds the check and phpseclib's decoder to agreement on known quirks and on
  three thousand generated inputs.

- Worked around a defect in the official Web eID validation library that
  refused roughly one ID-card authentication in 256. A card pads each half of an
  ECDSA signature to the width of the curve, so a half beginning with a zero
  byte is ordinary, and the library's conversion to DER keeps that zero even
  when it is superfluous, which OpenSSL then refuses. The signature is now
  re-encoded here before the validator sees it. Reported upstream as issue #71
  and fixed in pull request #74, neither released; remove the workaround when
  one is. The regression test stays green with or without it.

- The browser helper no longer reads an answer it cannot parse as an empty one.
  A 200 whose body is not JSON is now an error naming the status and quoting
  what came back, and a polling loop refuses anything that is not an object.
  Previously a PHP notice ahead of the JSON, or a proxy's error page, was taken
  for "not finished yet": the loop kept asking until the session it was waiting
  for had been finished and consumed, and then reported that no session was in
  progress. The authentication had succeeded.

- Replacing a signature file in a container that was read from bytes now
  actually changes those bytes. The writer re-emits original ZIP entries
  verbatim, which is what keeps other signatures valid when one is appended; it
  also silently discarded an archive timestamp at the moment of writing. Every
  test had archived a container built in memory, where there are no original
  entries to win, so the demo application found it first.

### Verified against

- Containers made by digidoc4j, including one that validates TOTAL-PASSED end
  to end once its PKI is trusted.
- The live Estonian test trusted list, SK's demo timestamp and OCSP services,
  and SiVa.
- Every Mobile-ID demo number SK publishes: each documented failure arrives as
  its own typed result, and containers signed by the ECC and the RSA demo
  number are TOTAL-PASSED in both our validator and SiVa.
- SK's Smart-ID demo accounts: authentication by account and by person, every
  documented refusal, a certificate choice, and RSA-PSS containers at SHA-256
  and SHA-512 that are TOTAL-PASSED in both our validator and SiVa.
- The live European list of trusted lists: its signature verifies against the
  certificates the Official Journal publishes, and the Estonian authorities
  behind every eID mean here are reached through it; Latvian and Lithuanian
  lists are reachable the same way.
- An archive timestamp digidoc4j made: our computation of what it covers
  digests to exactly the imprint its timestamp authority was asked to stamp.
  SiVa reads a container we archive as XAdES_BASELINE_LTA and passes it.

### Not yet

The ID card against real hardware, which needs a card, a reader and a person;
Smart-ID device-link flows against a live service, which needs someone to scan
a code; the manual DigiDoc4 checklist in `docs/manual-testing.md`, which is
written but unperformed; a smoke test against the production services, which
needs contracts with SK. Those four are what 1.0 waits for. BDOC-TM (time-mark)
signatures are not coming: SK stopped supporting them on 2023-11-01 and this
library reports them as unsupported rather than validating them.
