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

- **RSASSA-PSS beneath a signature.** Certificates, OCSP responses and
  timestamps signed with RSASSA-PSS are verified, where they used to be refused
  as an unsupported algorithm. The parameters are read from the algorithm
  identifier (`PssParameters`, `SignatureAlgorithmIdentifier::$pss`) and
  accepted in the one profile in use: SHA-256, SHA-384 or SHA-512, MGF1 with
  the same hash, a salt as long as the digest.

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
- `SmartIdAuthenticator` takes an `OcspClient` as its third argument, and
  `SmartIdConfiguration` has a `checkRevocation` flag with
  `withoutRevocationCheck()`.
- `WebEidConfiguration::MOBILE_ID_POLICY_PREFIX` is replaced by
  `MOBILE_ID_POLICIES`, the exact certificate policy OIDs refused by default.
- `LoggingHttpClient::withoutIdentities()` is now
  `HttpRequest::withoutIdentities()`, beside the new
  `HttpRequest::redactedUrl()`.
- `CertificateNotFoundException` no longer names the phone number and identity
  code in its message. They are on its new `identity` property, and what the
  service answered is on `result`.
- `Psr18HttpClient` no longer chains the PSR-18 client's exception as
  `previous`, because Guzzle and Symfony put the whole URL into its message.
  The message names that exception's class instead.
- The library's own log lines name nobody. Mobile-ID's "has no certificate"
  line gives only the service's answer, Web eID logs "authenticated
  PNOEE-[redacted]", and Smart-ID's debug line logs the URL without identity
  codes.
- `CurlHttpClient` gives connecting ten seconds by default, or the whole
  timeout when that is shorter; it used to give connecting the whole timeout.
  It takes `connectTimeoutSeconds` and `maxResponseBytes` as new arguments
  after the existing ones.
- `CurlHttpClient` and `Psr18HttpClient` refuse an answer larger than
  `HttpClient::DEFAULT_MAX_RESPONSE_BYTES`, 16 MiB, with a `TransportException`
  that names the limit. `Psr18HttpClient` takes the limit as its fourth
  argument, and a body that fails partway through is now a
  `TransportException` too.
- `MobileIdConfiguration`, `SmartIdConfiguration` and `SivaClient` refuse a URL
  that is not HTTPS, except plain HTTP to `localhost`, `127.0.0.1` or `[::1]`.
  Timestamp and OCSP URLs are not checked, because those services are plain
  HTTP.
- The signatures a signature rests on are held to algorithm constraints: on
  its certificate chain, its OCSP response and its timestamps. SHA-1 is
  refused, and so is an RSA key below 2048 bits, or below
  `ValidationPolicy::$minimumRsaKeyBits` where the `Allkiri` facade builds the
  clients. New: `AlgorithmConstraints`, `SignatureAlgorithmIdentifier`,
  `ValidationPolicy::algorithmConstraints()`, and a trailing constraints
  argument on `ChainBuilder`, `TspClient`, `TimestampTokenVerifier::verify()`
  and `OcspVerificationOptions`.
- New finding codes `CHAIN_WEAK_ALGORITHM`, `REVOCATION_WEAK_ALGORITHM`,
  `TIMESTAMP_WEAK_ALGORITHM` and `ARCHIVE_TIMESTAMP_WEAK_ALGORITHM`, reported
  as INDETERMINATE with the new sub-indication
  `CRYPTO_CONSTRAINTS_FAILURE_NO_POE`. New reasons: `REASON_ALGORITHM_NOT_ACCEPTED`
  on `ChainBuildingException`, `OcspVerificationException` and
  `TimestampVerificationException`, and `REASON_UNSUPPORTED_ALGORITHM` on
  `ChainBuildingException`.
- A certificate signed with an algorithm allkiri cannot verify now leaves a
  chain `CHAIN_NOT_FOUND` (INDETERMINATE) instead of `CHAIN_INVALID`
  (TOTAL-FAILED). When no chain can be built, the reason given is the failure
  that got furthest along a path rather than the last one tried.
- A signing certificate must have nonRepudiation in its key usage.
  `SigningService::prepare()` refuses one without it with the new
  `CertificateNotForSigningException`, and validation reports it as
  `SIGNING_CERTIFICATE_KEY_USAGE`, INDETERMINATE with the new sub-indication
  `CHAIN_CONSTRAINTS_FAILURE`.
- Certificate chains keep to each CA's constraints. New reasons
  `REASON_PATH_LENGTH` and `REASON_CA_KEY_USAGE` on `ChainBuildingException`,
  reported for the signer's chain as `CHAIN_CONSTRAINT_VIOLATED`. `Certificate`
  gains `pathLenConstraint()`, `isSelfIssued()` and `isExtensionCritical()`.
- A signature without a signature timestamp is INDETERMINATE with NO_POE and
  `TIMESTAMP_MISSING`, under the new `ValidationPolicy::$requireSignatureTimestamp`,
  which is true by default. With it off, a B-level signature is judged on its
  claimed signing time and carries `NO_POE_CLAIMED_TIME_USED`. New finding code
  `REVOCATION_NOT_BOUND_TO_SIGNING_TIME`.
- A trusted list past its next update, or naming none, is reported on each
  signature that rests on it as a `TRUSTED_LIST_EXPIRED` warning. The new
  `ValidationPolicy::$trustedListGraceSeconds`, null by default, refuses such
  anchors once the next update plus the grace period has passed. `TrustAnchor`
  gains a trailing `trustedList` argument and `withTrustedList()`; new
  `TrustedListStatus` and `WithoutExpiredListsTrustStore`.
  `TrustedList::isExpiredAt()` now counts a list with no next update as expired.
- `TrustedListLoader` writes a list to the cache only when it fetched it, not
  again when it read it from the cache.
- New finding code `TRUST_ANCHORS_UNAVAILABLE`, INDETERMINATE with
  NO_CERTIFICATE_CHAIN_FOUND, for a signature validated while the trust anchors
  cannot be loaded.
- `MobileIdPoller` and `SmartIdPoller` run on one internal polling loop. What
  each returns or throws is unchanged: Mobile-ID's `wait()` throws on a refusal
  or a timeout, Smart-ID's returns the status.
- `ContainerValidator::validateFile()`, `SmartIdSigner::startNotification()` and
  `SmartIdSigner::startDeviceLink()` default their options to a new
  `ValidationOptions` or `SigningOptions`, as every other method does, and no
  longer accept `null` for them. Leave the argument out instead.
- `Allkiri::httpClient()` builds the default `CurlHttpClient` once and returns
  the same one after that; it built a new one on every call. Mobile-ID and
  Smart-ID still get a client of their own, with a timeout long enough for
  their long polls.
- `AllkiriException` is an interface that every library exception implements,
  so `catch (AllkiriException)` still catches everything. The library's
  `InvalidArgumentException`, thrown for programmer and configuration errors,
  now extends SPL's `\InvalidArgumentException`: `catch (\InvalidArgumentException)`
  and `catch (\LogicException)` catch it, and `catch (\RuntimeException)` no
  longer does. Every other library exception extends `\RuntimeException`.
- Every restore of stored data, `fromJson()` and `fromArray()` on
  `DataToBeSigned`, `WebEidChallenge` and the sessions, throws the new
  `Allkiri\Exception\SessionDataException` when what was stored cannot be read
  back. What an object refuses after reading, and PHP's `ValueError`, arrive as
  its `previous`. The restores threw `InvalidArgumentException`, or let
  `ValueError`, `CertificateException` and `WebEidException` through.
- `SigningService` wraps a timestamp that cannot be had or trusted, and trusted
  lists that cannot be loaded, as `SigningException` with the original as
  `previous`, as it already did for chains and OCSP. A key of a type allkiri
  cannot sign with is refused in `prepare()` with
  `CertificateNotForSigningException`, and a prepared signature whose XML cannot
  be read is refused in `finalize()` with `SessionMismatchException`.
  `LtExtender` gains `requireTrustedSigner()`.
- `Allkiri::VERSION` and `Allkiri::USER_AGENT` are removed. The new
  `Http\UserAgent` builds the User-Agent, and its `version()` reads the installed
  version from Composer. `CurlHttpClient`'s `$userAgent` defaults to `null`,
  meaning `UserAgent::default()`. allkiri now requires `composer-runtime-api`
  ^2.0.
- `LtExtender`, `LtaExtender` and their result classes moved from
  `Allkiri\Xades` to `Allkiri\Signing`.
- The ASiC-E media type and the ASiC and manifest namespaces moved out of
  `Xades\Ns` into the classes they describe: `AsicContainer::MIME_TYPE`,
  `SignatureFile::NS_ASIC` and `Manifest::NS_MANIFEST`. `Xml::xpath()` no longer
  registers the `asic` prefix, which no query used.
- XML-DSig and the hardened XML loader moved out of `Allkiri\Xades` into
  `Allkiri\Xml`. `Xades\Dsig\Xml` is now `Xml\Xml`, which gains `load()`;
  `XmlDsigVerifier`, `Canonicalizer`, `ReferenceResolver`,
  `ArrayReferenceResolver`, `ReferenceResult`, `DsigVerificationResult` and
  `CanonicalizationException` are in `Xml\Dsig`. The XML-DSig namespace and
  algorithm URIs moved from `Xades\Ns` to `Xml\Dsig\DsigNs`. `Xml::xpath()`
  takes the prefixes to register, and `Ns::PREFIXES` holds the XAdES ones.
- Bytes that are empty, not well-formed or carry a DOCTYPE throw the new
  `Xml\InvalidXmlException` instead of `SignatureStructureException`.
  `XadesException`, `InvalidXmlException` and `CanonicalizationException` extend
  the new `Xml\XmlException`. So `archive()` on a signature file that is not XML
  no longer throws a `XadesException`, and `CanonicalizationException` is no
  longer one.
- `ZipBombException` and `UnsupportedZipException` moved from
  `Allkiri\Container\Zip` to `Allkiri\Container`, beside the
  `InvalidContainerException` they extend, and `AsicReader` and `AsicWriter`
  declare the ones they throw.
- Constructors take their internal collaborators last, after everything a
  caller configures. `SigningService` takes `logger` and
  `preparedSignatureTtlSeconds` before `builder`, `completer` and
  `dsigVerifier`; `TrustedListLoader` takes `clock` and `logger` before `parser`
  and `verifier`; `LtaExtender` takes `logger` before `data`; `OcspClient` and
  `TspClient` take `verifier` last.
- The library's machinery is marked `@internal` and can change in any release:
  the ASN.1, ZIP and XML readers and writers, XML-DSig verification, the XAdES
  build and parse classes, building and verifying OCSP and timestamp requests,
  the trusted-list parser and verifier, and the Smart-ID payload and status
  parser, together with the members of public classes that take or return them.
  `AsicContainer::$originalEntries` is private.

### Fixed

- The demo application kept the same session id after someone signed in, gave
  its session cookie no `HttpOnly`, `SameSite` or `Secure` flag, and accepted an
  id it had never issued. The id now changes at sign-in. The cookie is `HttpOnly`
  and `SameSite=Lax`, and `Secure` over HTTPS and always in live mode. PHP
  refuses ids it did not make. Scripts are served before the session starts, so
  they no longer wait behind a poll or set a cookie.
- The demo application kept uploads in a folder in the system's temporary
  directory, used that folder without checking who had created it, and named
  each file after the session id, which is a credential. Another account on a
  shared machine could read or replace them. Containers now live in the
  gitignored `examples/demo-app/var/`, created 0700, under a random name the
  session remembers.
- The demo application answered any request, by any method and from any site:
  a form elsewhere could start a Mobile-ID or Smart-ID request to a phone,
  replace the card challenge, consume a finished session, or buy a timestamp in
  live mode. Every call that changes something is now a POST carrying a token
  the page holds, which `allkiri.configure()` and the page's two uploads send;
  the download is the one GET. No page of the demo can be framed, and a download
  before any upload is a JSON error rather than a crash.
- `LtExtender`, asked for LTA, said archive timestamps were not implemented,
  although `LtaExtender` and `SigningService` add them. It now says that, and
  `docs/signing.md` lists LTA among the levels.
- The User-Agent sent to SK, RIA and Zetes said `allkiri/0.1.0-dev` whatever was
  installed. It now names the installed release, or the branch and commit of a
  branch install.

- Text that is not UTF-8 is refused where it enters, instead of escaping later
  as PHP's `\JsonException` when a request is encoded. Smart-ID interaction text,
  the Mobile-ID and Smart-ID relying-party names, Mobile-ID display text and a
  Smart-ID callback URL are refused with `InvalidArgumentException`, and a file
  name sent to SiVa with `SivaException`. `SmartIdClient` now applies the
  callback URL check the authenticator and signer already applied.
- A certificate that names its OCSP responder at an address that is not http(s)
  no longer makes `OcspClient::fetch()` throw `InvalidArgumentException`. The
  address is skipped; without an http(s) one the default responder is asked, or
  `OcspException` reports that none is known. A list of trusted lists that
  places a national list at such a location is refused with
  `TrustedListException`. `HttpRequest::isHttpUrl()` is new.
- A container with an entry whose name an unzip tool would place outside its
  folder, such as an absolute path, a `..` segment, a backslash or a NUL byte,
  is reported as `NOT_A_CONTAINER`. A data file named that way made
  `ContainerValidator::validate()` throw `InvalidArgumentException`, and such
  an entry under `META-INF/`, or a directory entry, was not refused at all.
- A prepared signature no longer lasts for ever. `finalize()` refuses one
  prepared more than ten minutes earlier, by the signing time the signature
  carries, with the new `PreparedSignatureExpiredException`, and one dated more
  than five minutes ahead of the server's clock, before a timestamp is bought.
  The limit is the new trailing `preparedSignatureTtlSeconds` argument of
  `Allkiri` and `SigningService`.
- The signer's certificate chain is checked in `prepare()`, at level T and
  above, and again in `finalize()` before a timestamp is bought. It was first
  checked after the timestamp had been bought, and at level T not at all, so an
  untrusted signer cost a timestamp and at T was given one.

- A bundled resource that cannot be read throws `InvalidArgumentException`
  instead of an anonymous exception class that could not be caught by name, and
  a node outside any document handed to the signature parser throws it instead
  of PHP's `\LogicException`.

- Stored sessions, prepared signatures and Web eID challenges are read back by
  one reader, so they all refuse malformed data the same way. Before, a stored
  Mobile-ID session whose challenge was not base64 was restored with an empty
  challenge, an unknown algorithm or level in a stored `DataToBeSigned` threw
  PHP's `ValueError`, and dates were parsed loosely, so "now" was accepted. Each
  is now refused with `SessionDataException`, with a message naming the field
  and never its value.
- A stored Smart-ID session with a missing field no longer puts the whole stored
  array, session secret included, into the exception's stack trace. Every
  `fromArray()` and `fromJson()` now keeps its input out of stack traces.

- Validation no longer throws when the trust anchors cannot be loaded. A
  trusted list that could not be fetched, verified or parsed escaped from
  `SignatureValidator` and `ContainerValidator` as a `TrustedListException`.
  Each signature now reports it as `TRUST_ANCHORS_UNAVAILABLE`, and what was
  found before stands.

- A signature resting on a trusted list past its next update is no longer
  reported as if the list were current. It validated TOTAL-PASSED with no
  finding, and the only trace was a log line when the loader had a clock. A
  cached list was also written back on every read, which kept renewing the
  entry, so it was never fetched again.

- Without a verified timestamp, a revocation answer is held to the claimed
  signing time. An embedded OCSP response was compared only with itself: a
  signature whose timestamp had been removed validated TOTAL-PASSED with an
  answer from years before or after, and one whose timestamp failed said nothing
  about how far its answer lay from the claimed time. The answer must now have
  been produced after the claimed signing time, within the policy's OCSP window
  of it, and not after the validation time. A signature with neither a timestamp
  nor a signing time no longer skips its chain check silently.

- A revoked OCSP response is no longer outweighed by a good one embedded before
  it. When a signature carried several responses, the first that verified was
  used, whatever it said. A revoked answer now decides. Otherwise the newest
  answer produced within the policy's OCSP window after the signature time is
  used, and the newest overall only when none falls inside the window.

- Certificates and tokens that do not parse are reported rather than thrown.
  `SignatureValidator` promises never to throw on bad input, but three kinds of
  input escaped it as exceptions, and the OCSP and timestamp clients too:
  - a malformed certificate inside an OCSP response or a timestamp token;
  - a timestamp token with more than one signer;
  - a certificate whose public key cannot be loaded.

  Each is now an ordinary finding, or a reason on the clients' own exceptions.

- A certificate is now judged for the job it does. Three checks were missing.
  A certificate without nonRepudiation, such as an authentication certificate
  from a trusted CA, made signatures that validated as TOTAL-PASSED, and
  allkiri would make them. A CA's path length constraint was ignored, and so was
  an intermediate whose key usage does not allow it to issue certificates. And
  a timestamp authority certificate that does not mark its timestamping purpose
  critical, as RFC 3161 requires, was accepted.

- SHA-1 and small RSA keys are no longer accepted beneath a signature. The
  validation policy's algorithm floor reached only the XAdES signature method
  and references. Certificates, OCSP responses and timestamps were verified
  with SHA-1 allowed and no key-size floor, so a chain link, a revocation
  answer or a timestamp signed with SHA-1 passed validation with no finding,
  and signing and sign-in accepted them too. They are now refused wherever
  allkiri signs or signs someone in. Validation reports them as INDETERMINATE:
  the signature was not forged, but what it rests on can no longer be relied
  on, and nothing shows it was made while SHA-1 still counted. A certificate
  whose two signature algorithm fields differ, which RFC 5280 forbids, is no
  longer treated as signed by anyone.

- A server can no longer make the library hold an answer of any size. Both
  HTTP clients read the whole body into memory with no limit, from every
  service they call, including OCSP responders named inside the certificates
  being validated, so a single oversized answer could exhaust a PHP worker. An
  unreachable host also held a worker for the full timeout, because connecting
  was given all of it. And a Mobile-ID, Smart-ID or SiVa URL mistyped as
  `http://` was accepted, sending the relying-party identifier, identity codes
  or whole containers in clear text.

- Identity codes no longer reach logs through failed calls.
  `LoggingHttpClient` removed them from the URL it logged, but logged the
  failure's message and exception beside it, and the cURL and PSR-18
  transports put the whole URL into that message. A refused connection to
  `/v3/signature/certificate/PNOEE-…` therefore carried the code into any log
  that printed the error, and the Mobile-ID and Smart-ID status errors repeated
  the URL in messages applications log themselves. The library's own logger
  named people outright: the phone number and identity code of someone without
  Mobile-ID, everyone Web eID signed in, and every Smart-ID request path at
  debug level. Every message the library builds around a URL now shows it
  without identity codes, and its log lines name nobody. `docs/logging.md`
  lists the exception messages that still name a person, because naming the
  certificate is the diagnosis.

- Passwords, private key material, Smart-ID session secrets and relying-party
  identifiers are marked `#[\SensitiveParameter]`. A stack trace in an error log
  now shows them as `SensitiveParameterValue` instead of the value. This
  protects trace arguments only: the objects that hold these values still show
  them to `print_r()`, and a serialised Smart-ID session still carries its
  secret, which is why it must stay on the server.

- Web eID sign-in refuses Mobile-ID certificates issued under the policy SK has
  used since 2022, `1.3.6.1.4.1.10015.18.1`. allkiri named
  `1.3.6.1.4.1.10015.1.3` as a prefix, but the Web eID library compares
  policies exactly, so the prefix added nothing and neither refused the newer
  policy. The default is now the exact list. The documentation says that an
  empty list does not admit the Mobile-ID policies the library refuses on its
  own.

- Smart-ID sign-in now checks that the authentication certificate has not been
  revoked. SK's response verification guidance asks relying parties to, and
  allkiri did not, so a revoked certificate still signed in. The certificate's
  OCSP responder is asked, and sign-in is refused when the answer is revoked,
  unknown or cannot be had. The check can be turned off for a test
  environment, as the ID card's can. SK's Mobile-ID checklist does not ask for
  revocation, and the Mobile-ID guide now says so.

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
