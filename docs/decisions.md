# Decisions and spike results

Facts established by running code, recorded so nobody has to rediscover them.
Dates are when the spike ran.

## 2026-09-11 — Phase 1 step 0 spikes

### ZIP writing with `ZipArchive` is good enough

libzip 1.11.2 (PHP 8.4, Windows) writes `mimetype` as the first entry, STORED,
with no extra field and no data descriptor when it is added first and
`setCompressionName('mimetype', ZipArchive::CM_STORE)` is called. Reopening
the archive and adding `META-INF/signatures0.xml` left every original local
record byte-identical and appended the new entry last.

Decision: `ZipArchive` is the writer. A small own reader parses the central
directory and local headers for the structural checks the validator needs
(entry order, method, extra-field length), which `ZipArchive` does not expose.
Byte-level tests guard the writer's behaviour so a different libzip shows up
in CI.

### Exclusive canonicalisation via `DOMNode::C14N` matches DSS/digidoc4j

For every digidoc4j test container tried (ECDSA P-256, ECDSA P-384, RSA,
LTA, two signatures in one container) the SignedProperties reference digest,
the data-file digests and the SignatureValue all verified using
`$node->C14N(true, false)` on a document loaded with `preserveWhiteSpace`.
ECDSA values verify with phpseclib's `IEEE` signature format (raw r‖s).

Only a 2013 libdigidocpp sample used `xml-c14n11`, which `DOMNode::C14N`
cannot produce; such legacy signatures are reported as unsupported.

### What digidoc4j actually emits (layout to mirror)

- XML declaration `standalone="no"`; `ds` namespace declared on
  `ds:Signature`, `xades` on `xades:QualifyingProperties`, `asic` on the root.
- Ids: `id-<32 hex>`, references `r-id-<hex>-1`, SignedProperties
  `xades-id-<hex>`, SignatureValue `value-id-<hex>`, timestamp `TS-<uuid>`
  with `EncapsulatedTimeStamp Id="ETS-<uuid>"`.
- `xades:SigningCertificate` (v1) with `ds:X509IssuerName` in Java/DSS
  RFC 2253 form, unknown attribute types as numeric OID with a hex-encoded
  DER value (`2.5.4.97=#0c0e…`). allkiri emits `SigningCertificateV2` by
  default (byte-exact `IssuerSerialV2`, EN 319 132-1) and parses both; v1 is
  available through the signature profile if a validator ever demands it.
- `SignatureTimeStamp` carries an explicit exclusive `ds:CanonicalizationMethod`.
- `CertificateValues` contains the TSA certificate, the TSA CA, the OCSP
  responder certificate and the full signer chain including the root. A
  container with no `CertificateValues` at all (`NoAdditionalCertificates_LT`)
  is still a valid LT signature.
- Manifest: `manifest:version="1.2"`, root entry `full-path="/"` with the
  ASiC-E media type, one entry per data file.

### phpseclib ASN.1 engine: rules that cost an afternoon

- `decodeBER` nodes carry `start`, `headerlength` and `length`; **`length`
  already includes the header**. The exact DER of a node is
  `substr($der, $node['start'], $node['length'])`. Offsets are absolute to
  the buffer passed to `decodeBER`; never slice one buffer with offsets from
  another buffer's tree.
- `TYPE_ANY` in `asn1map` returns primitives as a one-key array keyed by type
  name (`['octetString' => …]`) and constructed values as `ASN1\Element`
  holding the raw DER. Attribute values are therefore always taken from the
  raw tree.
- BIT STRING content includes the leading unused-bits byte; strip it for
  signature values and for the SPKI key hash in an OCSP CertID.
- GeneralizedTime: the mapped value is a string formatted through a global
  setting; the raw node's `content` is a `DateTime`. Read times from the raw
  tree.
- phpseclib names almost no OIDs outside X.509: no SHA-2 digest OIDs, no CMS,
  TSP or OCSP OIDs. allkiri keeps its own OID table and compares numerically.
- `X509::getPublicKey()` returns RSA keys with PKCS#1 v1.5 signature padding
  preselected; RSA-PSS must be configured explicitly.
- ECDSA: `withSignatureFormat('IEEE')` gives fixed-width r‖s (64 bytes for
  P-256, 96 for P-384) and `IEEE::save($r, $s, $curve, $bits)` /
  `ASN1::load()` convert between the two formats.

### Demo services behave as the plan assumed

- TSA `http://tsa.demo.sk.ee/tsa`: RFC 3161 over HTTP, policy 0.4.0.2023.1.1,
  TSU "DEMO SK TIMESTAMPING UNIT 2025E" (P-256, ecdsa-with-SHA512, SHA-512
  message digest attribute), `ESSCertIDv2` with issuerSerial, TSU certificate
  included when `certReq` is set, nonce echoed, accuracy 1 s. The CMS
  signature verifies over the `signedAttrs` slice with its first byte rewritten
  from `0xA0` to `0x31`.
- OCSP `http://demo.sk.ee/ocsp` and the AIA responders
  (`http://aia.demo.sk.ee/esteid2018`): our own DER request with a nonce
  extension is accepted; both echo the nonce; responder certificates are
  delegated (issued by the CA being queried, EKU `id-kp-OCSPSigning`, no
  `ocsp-nocheck`), `sha256WithRSAEncryption` with 3072-bit keys, and the
  commercial responder's certificate rotates monthly
  ("TEST of ESTEID2018 OCSP RESPONDER 202609"). `responderID` is `byName`
  and equals the responder certificate's subject DER.
- Test trusted list `EE_T.xml`: enveloped XAdES signature with exclusive
  c14n, `rsa-sha256`, SHA-256 digests, a SignedProperties reference; signer
  `C=EE, CN=Test TSL` valid until 2028-11-12. The same XML-DSig verifier
  used for containers verifies it.

## 2026-09-11 — the demo certificate upload service

`https://demo.sk.ee/upload_cert/` accepts any X.509 certificate with an AKI
extension and makes `http://demo.sk.ee/ocsp` answer for it. Two things about
it are worth knowing before relying on it.

**The answer is signed by a shared responder.** For an uploaded certificate the
response comes from "DEMO of KLASS3-SK 2016 OCSP RESPONDER", which the uploaded
certificate's own CA did not issue. RFC 6960 authorises a responder in three
ways: it is the CA itself, it is a responder the CA issued carrying the
OCSPSigning extended key usage, or the client trusts it explicitly. Only the
third applies here, so allkiri refuses such a response unless the responder is
named as a trusted responder. That is not a bug to work around; it is the only
correct reading, and the integration test names the responder deliberately.

**The certificate's own AIA still points wherever it points.** allkiri asks the
responder a certificate names before falling back to any default, so a test
certificate with a made-up AIA URL needs an override for its issuer.

### What SiVa says about a container allkiri signs

Signed with our own test CA against the demo timestamp and OCSP services,
then sent to SiVa demo (2026-09-11):

```
SiVa: policy=POLv4 form=ASiC-E signatures=1 valid=0
  indication=INDETERMINATE sub=NO_CERTIFICATE_CHAIN_FOUND format=XAdES_BASELINE_LT
  signedBy=Allkiri test e-seal
  ERROR: The certificate chain for signature is not trusted, it does not contain a trust anchor.
  ERROR: Unable to build a certificate chain up to a trusted list!
```

Everything structural is accepted: the container is ASiC-E, the signature is
recognised as XAdES_BASELINE_LT, and SiVa reads back the signer, the signing
time, the timestamp time and the OCSP time we wrote. The only complaints are
that it has no reason to trust a CA we invented, which no format change could
fix.

Worth noting for the validator: SiVa reaches `INDETERMINATE` with
`NO_CERTIFICATE_CHAIN_FOUND`, which is exactly what allkiri reports for the
same situation. The two agree on the mapping, not only on the outcome.

### Tooling

- The shell transport truncates commands above roughly 8 KB, which surfaces
  as `unexpected EOF while looking for matching quote`. Files longer than a
  couple of kilobytes are written with the editor tool, not heredocs.
- OpenSSL 3.5 CLI is available locally and used as the independent
  cross-check (`openssl ts`, `openssl ocsp`, `openssl asn1parse`).

## 2026-09-12 — Phase 2, Mobile-ID

### Display text is measured in characters, and bad characters are not refused

SK's API reference says the display text is "maximum 100 bytes, that is either
50 or 100 characters depending on the encoding", and then gives the real
limits per format: GSM-7 takes **100 characters** of the GSM 03.38 alphabet
including at most **5** from the extension table `€[]^|{}\`, and UCS-2 takes
**50 characters**. Counting bytes, as a first reading of "100 bytes" suggests,
is wrong in both directions: it under-counts extension characters, which cost
two, and over-counts any non-ASCII letter, which costs one.

The trap underneath is worse than the arithmetic. A character GSM-7 cannot
carry is **replaced with a space**, not refused, so the request succeeds and
the person simply reads a mangled sentence on their phone. Estonian `õ`, `š`
and `ž` are all outside GSM-7, which makes `Nõustun` — about the most likely
word to put on a signing prompt — arrive as `N ustun`.

`MobileIdConfiguration` therefore refuses such text at construction and names
the offending characters, and `DisplayTextFormat::forText()` picks a format
that carries what it is given.

### Mobile-ID returns DER-encoded ECDSA values

XML-DSig carries ECDSA as raw `r‖s`; Mobile-ID hands back DER. The conversion
already existed inside `SigningService::finalize()`, which is why signing
worked immediately, but the authentication path verified the value directly
and rejected every real answer. Both now go through
`EcdsaSignature::toRaw()`, which detects the shape rather than trusting the
source, so a third path cannot quietly acquire the same bug.

### A long poll needs an HTTP timeout longer than itself

The status endpoint holds the request open for `timeoutMs` before answering.
SK's own note is to allow roughly 1500 ms more than that; allkiri allows five
seconds, and `Allkiri::mobileIdClient()` builds the client with a timeout that
fits instead of reusing the environment's 30-second default, which a 60-second
poll would otherwise outlive. The configuration also refuses a poll timeout
above 60 seconds, because the service silently substitutes its own maximum.

### Connecting gets less time than answering

`CurlHttpClient` gave connecting the whole timeout, so an unreachable host held
a worker for 30 seconds, and for longer behind a long poll. Connecting, TLS
included, now gets ten seconds by default, or the whole timeout when that is
shorter. That is ample for SK's services and still fails a dead host quickly.
The whole-call timeout is unchanged, because a long poll rightly takes as long
as it asked for.

### An answer has a size limit

Nothing allkiri fetches is large. The largest national trusted list the European
list of lists linked to in September 2026 was Germany's, at 5.4 MB, and
everything else is kilobytes. Both built-in clients refuse an answer over
16 MiB, three times that, instead of buffering whatever a server sends; OCSP
responder URLs come from certificates, so the server is not always one you
chose. cURL is given the limit, which refuses an announced length before the
body is read, and the body is counted as it arrives for an answer that
announces none. An answer over the limit is refused rather than truncated,
because part of a trusted list is not a smaller valid one.

### What a signature rests on meets the same algorithms as the signature

A signature is only as strong as the signatures beneath it: those on its
certificate chain, its revocation answer and its timestamps. allkiri held the
XAdES signature itself to SHA-2 and a 2048-bit RSA floor, and verified
everything beneath it with SHA-1 still allowed and no floor at all. Both now
meet the same floor, when a signature is made and when someone signs in as well
as when a signature is validated.

In validation, a weak algorithm beneath a signature is INDETERMINATE with
`CRYPTO_CONSTRAINTS_FAILURE_NO_POE`, not TOTAL-FAILED. Nothing was forged; what
is missing is proof that the signature existed while its algorithm still
counted. allkiri does not yet treat archive timestamps as that proof, so an
archived container with a SHA-1 link reads as indeterminate. SiVa's BDOC policy
only warns on SHA-1, so the two can disagree about such containers.

Verifying an algorithm and accepting it are separate steps. SHA-1 is still
verified, so a signature made with it is reported as weak rather than as
unreadable or forged. An algorithm allkiri cannot verify at all is no evidence
of forgery either, so a chain that meets one is reported as not found rather
than invalid.

When several paths are tried and none works, the reason given is the failure
that got furthest along one. Otherwise the last candidate tried, often a
certificate that merely shares a name with the real issuer, would decide the
verdict.

### RSASSA-PSS beneath a signature takes one profile

Certificates, OCSP responses and timestamps signed with RSASSA-PSS are accepted
only with SHA-256, SHA-384 or SHA-512, MGF1 over the same hash, a salt as long
as the digest, and the standard trailer. That is what RFC 4055 recommends and
what OpenSSL and phpseclib write. Nothing else is in use, and each other
combination would be one more way to be wrong about a signature.

The parameters are read field by field rather than through phpseclib's map,
because that map fills in defaults. An absent hash means SHA-1 and an absent
salt length means 20 bytes, and both have to be refused rather than read as
something else. The parser is checked against a certificate OpenSSL issued as
well as against the test encoder.

One limit remains. phpseclib does not check that a PSS signature's salt has the
length it is told to expect, so the parameters are checked as declared, and a
signature made with another salt length would still verify. That is not a
forgery risk, and enforcing it would mean switching a phpseclib setting that is
global to the process.

### A certificate is judged for the job it does

A signing certificate must carry nonRepudiation, as ETSI EN 319 412-2 requires
of certificates for electronic signatures. digitalSignature is not required,
because SK's signing certificates carry nonRepudiation alone. A signature by a
certificate without it is INDETERMINATE with `CHAIN_CONSTRAINTS_FAILURE`, not
TOTAL-FAILED. That matches how ETSI EN 319 102-1 treats a certificate that fails
a validation constraint, and so what SiVa reports. The signing service refuses
such a certificate before anything is built.

A CA's path length constraint is held to as RFC 5280 counts it, and a trust
anchor's limit is held to as well; none of the Estonian chains in the fixtures
comes near a limit. An intermediate that restricts its key usage must allow
keyCertSign.

A timestamp authority's certificate must mark its timestamping purpose
critical, as RFC 3161 requires, and every SK TSA certificate seen does. An OCSP
responder's certificate is not held to the same: RFC 6960 does not ask for it,
and several of SK's responder certificates mark OCSPSigning non-critical.

### Several revocation answers: a revoked one decides

A signature can carry more than one OCSP response, when a tool extends it again
or someone adds one. allkiri used the first that verified, so a good answer
placed before a revoked one decided the verdict. A revoked answer now decides
wherever it sits, because a good answer beside it says nothing about the
revocation.

Among the rest, the newest answer produced within the policy's OCSP window after
the signature time is used. Plain "newest" would let an answer added days later
fail the timestamp-to-OCSP order check on its own lateness and take a sound
signature down with it. Only when no answer falls inside the window is the
newest overall used. How DSS and digidoc4j choose between answers was not
checked.

### A claimed signing time proves nothing, so revocation is held to it

A signature timestamp is what proves when a signature existed. Without one, the
only time available is the one the signer wrote into the signed properties, and
that can be written to suit a stale revocation answer. allkiri compared an
embedded OCSP response only with itself. A signature whose timestamp had been
deleted validated TOTAL-PASSED as XAdES_BASELINE_B, with an answer from years
before or after, and one whose timestamp failed was indeterminate with nothing
about its revocation answer.

A signature without a timestamp is now INDETERMINATE with `TIMESTAMP_MISSING`
unless the policy's `requireSignatureTimestamp` is switched off. SiVa does not
accept B-level ASiC-E signatures either. When no timestamp verifies, whether
absent or broken, the chosen revocation answer must have been produced after the
claimed signing time, within the policy's OCSP window of it, and not after the
validation time. Otherwise `REVOCATION_NOT_BOUND_TO_SIGNING_TIME` names the
bound that failed. It carries NO_POE rather than TRY_LATER, because a fresher
answer fetched later cannot say anything about the claimed moment; only proof of
when the signature existed could.

The bound against the validation time applies only on this path. Holding a
timestamped signature to the validation time is part of making `validationTime`
drive validation at all, which is not done yet. A signature with neither a
timestamp nor a signing time used to skip its chain check without a word; it now
carries the same finding.

### An overdue trusted list is named, and refused only on request

A trusted list names the date its successor is due. allkiri used a list past that
date without a trace in the report: a container validated TOTAL-PASSED against
it, and the only sign was a log line, written only when the loader had a clock.
Anchors did not know which list they came from, so neither a national list's
next update nor that of the list of lists reached them.

Each anchor now carries its list's label and next update, and the list of lists
it was reached through. A signature whose CA, timestamp authority or directly
listed responder rests on an overdue list carries a `TRUSTED_LIST_EXPIRED`
warning. DSS treats TLNotExpired as a warning by default; SiVa and digidoc4j
fail it. A warning is the default here because a failure would turn every
signature INDETERMINATE the moment a publisher is late, and how late publishers
actually run was not measured. For the same reason no grace period is
suggested: `ValidationPolicy::$trustedListGraceSeconds` refuses the anchors once
the next update plus that period has passed, and `0` refuses them at once.

A refused anchor gives the sub-indication its absence would, so a caller that
branches on NO_CERTIFICATE_CHAIN_FOUND, NO_POE or TRY_LATER sees the same thing
whether the anchor was never configured or came from a stale list; the finding
code tells them apart. A list with no next update counts as overdue, as DSS
treats it.

The loader wrote a list back to the cache on every read. That renewed the
entry's lifetime each time, so under steady use a cached list was never fetched
again and would have stayed overdue. It is now written only when fetched.

### Trust anchors that cannot be loaded are a finding

`SignatureValidator` promised never to throw, but a trusted list that could not
be fetched, verified or parsed escaped as a `TrustedListException` from the
first check that needed an anchor. Production trust is loaded over the network
on first use, so a caller validating a container got an exception instead of a
report whenever the list's publisher could not be reached.

The checks that need trust now run inside one catch. The signature gets
`TRUST_ANCHORS_UNAVAILABLE`, INDETERMINATE with NO_CERTIFICATE_CHAIN_FOUND,
which is what an unknown CA gives, and a message carrying the list's reason.
Findings made before the failure stay, so a changed data file is still
TOTAL-FAILED. The failure is not remembered: each signature tries the lists
again, which with the network down means waiting out the HTTP timeouts once per
signature. Signing and signing in still throw, because they have no report to
put the problem in.

### The new certificate profile reversed the common name

Certificates issued under `TEST of ESTEID-SK 2015` carry
`CN=SURNAME,GIVENNAME,IDENTITYCODE`. The profile in use since 2019, under
`TEST of EID-SK 2016` and `TEST of SK ID Solutions EID-Q 2021E`, carries
`CN=GIVENNAME,SURNAME` with no code at all. `AuthenticatedIdentity` reads the
`serialNumber`, `SN`, `GN` and `C` attributes, which both profiles have, and
only falls back to splitting the common name when it has exactly three parts —
a two-part common name says nothing about which half is the surname.

### PHP identifiers can contain high bytes

`"@£$¥è…"` in a double-quoted string is not the literal it looks like: PHP
allows bytes ≥ 0x80 in identifiers, so `$¥èéùìòÇ` parses as a variable, and a
constant built from that string fails to compile with "Constant expression
contains invalid operations". The GSM-7 alphabet constant is single-quoted
with the two control characters concatenated separately.

### What the demo numbers actually do

All of SK's published test numbers behave as documented (2026-09-12). The
positive ones are slow on purpose: `+37200000766` answers in about 7 seconds
and `+37200001566` in about 15, which is why these are integration tests.

Containers signed by both the ECC and the RSA demo number are **TOTAL-PASSED**
in SiVa demo and in allkiri's own validator. That closes the Phase 1 gate that
was waiting on a key anchored in the test trusted list: these certificates are
issued by CAs the list carries, so `ALLKIRI_TEST_P12` is no longer needed for
anything but exercising the same path with a local key.

## 2026-09-12 — Phase 3, Smart-ID v3

The RP API v3 reference pages are not in SK's public documentation repository,
so the protocol here was read from their own v3 clients
(`SK-EID/smart-id-java-client`, which covers signing, and
`SK-EID/smart-id-php-client`, which covers authentication only) and then checked
against the live demo service. Four things only the second step revealed.

### A notification authentication requires `vcType`, and returns no code

`POST /authentication/notification/...` is rejected with HTTP 400 and
`Null argument found: /vcType` unless the request says which shape of
verification code the app should show; the only value is `numeric4`. The
response then carries **no** verification code at all: the relying party derives
it from the challenge it just sent, and both sides arrive at the same four
digits.

A notification *signature* is the other way round. It takes no `vcType` and its
response carries `vc` with a `type` and a `value`. A `type` other than
`numeric4` is refused rather than shown, because the person compares the code
character by character.

### A certificate choice signs nothing, and still sends a `signature`

A completed certificate-choice session answers with a `signature` object
containing only `flowType`, no value and no algorithm, plus the certificate and
the document number. Requiring a signature on every successful session — which
is right for authentication and for signing — makes that unreadable. What marks
a real signature is therefore a non-empty `value`, not the object being present,
and the parser now reads what is there while each flow requires what it needs,
which is how SK's own validators are arranged.

`interactionTypeUsed` is likewise absent from a certificate choice, so it moved
from the parser to the authenticator, which genuinely cannot do without it: it
is one of the eleven parts of the signed payload.

### The PSS profile SK uses is exactly the one RFC 6931 fixes

Smart-ID keys are RSA, and SK deprecates PKCS#1 v1.5 in favour of
`rsassa-pss`. Their own client refuses any answer whose salt is not the digest
length, whose mask generation function is not MGF1 over the same hash, or whose
trailer field is not `0xbc`. That is precisely the profile the
`…xmldsig-more#sha256-rsa-MGF1` family of XML-DSig methods describes, so a
Smart-ID signature fits `PS256`/`PS384`/`PS512` unchanged and no explicit
`RSAPSSParams` element is needed.

This matters more than it looks. The XAdES declares its signature method before
the signature exists, so a value produced with different parameters would make
the container describe itself wrongly. The library therefore checks the reported
parameters against the profile and refuses to finalize rather than writing out a
container no validator could accept. The same check rejects a session that
answers in a different algorithm from the one it was prepared for.

The API also accepts SHA-3, which has no signature method in the profile we
produce; such an answer is refused with that explanation.

### Verification code: the last two bytes, modulo ten thousand

The unsigned 16-bit big-endian integer formed by the last two bytes of the
SHA-256 of the data, then its last four decimal digits. SK's Java client
expresses the modulo as string padding and slicing, which reads like it could
produce five digits and cannot. All six of their published vectors match.

### Device links are the one place a string must be exact

The app rebuilds the authentication code itself, so the query parameters have to
appear in the order `deviceLinkType`, `elapsedSeconds` (QR only), `sessionToken`,
`sessionType`, `version`, `lang`, and the HMAC covers eight pipe-joined parts
ending with that whole URL. A QR link's elapsed seconds are inside the code, so
each second needs a new link and a new code, which is why the session secret
stays on the server and only finished links reach the browser.

Session types in a link are `auth`, `sign` and `cert`; a certificate choice
contributes an empty signature protocol to the payload rather than a name.

### Certificate profiles vary more than expected

`PNOEE-50001029996-DEMO-Q` has `CN=TEST,OK` with `SN=TEST` and `GN=OK`: the
common name is surname-first here, where the profile on the Mobile-ID demo
numbers is given-name-first. Reading `serialNumber`, `SN`, `GN` and `C` rather
than splitting the common name is what makes both work, and is why the two-part
common name is never split.

### What the demo accounts actually do

Authentication, refusals and signing all behave as documented (2026-09-12).
Containers signed with SHA-256 and SHA-512, by accounts under both
`TEST of SK ID Solutions EID-Q 2021E` and `EID-Q 2024E`, are **TOTAL-PASSED** in
SiVa demo and in allkiri's own validator. These are the library's first RSA-PSS
signatures accepted end to end, which settles the Phase 1 risk that noted PSS
might be rejected.

Device-link flows are not integration-tested: completing one needs a person to
scan a code, and SK drives that through a mock service their client knows about.
Their own repository disables the linked-notification test with the note that
device-link demo accounts are not currently testable. The link construction is
pinned offline instead.

## 2026-09-12 — Phase 4, Web eID and production trust

### What the dependency does, and what it does not

The plan was to depend on `web-eid/web-eid-authtoken-validation-php` rather than
reimplement the authentication token check, and that holds: the token format,
the signature over origin and challenge, and the certificate's key usage and
policies are its job. Two things are not.

Its `ChallengeNonceStore` is a concrete class that writes to `$_SESSION` and
throws if there is none. allkiri never touches sessions, and its validator takes
the nonce as a plain string, so the challenge is generated here and the store is
not used at all.

Its OCSP checking is switched off and allkiri's own is used instead. Phase 1
recorded why that implementation is not the one to build on, and beyond that a
library with one OCSP client, one trust store and one chain builder judges a
card exactly as it judges a Mobile-ID or Smart-ID certificate. The chain check
runs twice as a result, theirs as a precondition of their own batch and ours for
the verdict, both against the same anchors.

### A malformed token reaches a TypeError

`AuthTokenValidatorImpl::validateToken()` checks `format` and
`unverifiedCertificate` for null but not `algorithm` or `signature`, and passes
both straight into a method with `string` parameters. A token missing either
therefore throws `TypeError`, which is outside the library's own exception
hierarchy: an application catching `AuthTokenException` would serve a 500 for
what is simply a malformed request. Everything thrown inside that call is
caught and turned into a refusal, deliberately including `Throwable`, because
that call is the boundary where an attacker-supplied string is interpreted.

### The padding is decided by the card and reported afterwards

`getSigningCertificate()` returns what the card supports as
`{cryptoAlgorithm, hashFunction, paddingScheme}` triples, but `sign()` takes
only the hash function. The card picks the padding and names it in the reply.

That is the same shape of problem as Smart-ID: the XAdES declares its signature
method before the signature exists. So the padding is worked out in advance from
the published list, and the reported algorithm is checked against what was
prepared, refusing rather than writing a container that declares a method it
does not use. `CardAlgorithm` is where the browser's three fields and XML-DSig's
single URI meet; SHA-224 and SHA-3 are reported by some cards and map to
nothing, so they are passed over rather than guessed at.

### The origin must be the browser's, exactly

The token carries neither the origin nor the challenge, which is the whole point
of the format: the server is forced to supply both from its own storage, so a
token cannot be relayed from another site and cannot be replayed against another
session. It also means an origin that differs by one character verifies nothing.
`WebEidOrigin` builds the ASCII serialisation: https only, no path, default port
443 dropped because a browser omits it, and an internationalised host converted
to Punycode.

### Production trust: the full chain, not a pinned fallback

Phase 1 left this open — verify the European list of trusted lists properly, or
fall back to pinning the Estonian list's signing certificates. The full chain
turned out to be straightforward, because Phase 1's parser already reads
pointers and their signing certificates, so it is what shipped.

The live list of lists (sequence 393, 3 September 2026) verifies with allkiri's
own verifier against a certificate published in Official Journal C/2026/1944.
All six certificates that publication lists are shipped in `resources/trust/eu`
with their digests and their provenance. Nothing else is pinned: where the
Estonian list lives, which certificates may sign it, and which services it
publishes are all read from the verified list of lists, so a national list can
rotate its signing certificate without a release here.

`ListOfListsLiveTest` fails when the list of lists is signed by something not in
that directory, which is the only warning that the Journal has published a new
set.

### A territory has two pointers, and the PDF may come first

Each territory points at its list twice: once as `application/vnd.etsi.tsl+xml`
for a program and once as `application/pdf` for a person. `pointerTo()` returned
the first match, and in the European list the Estonian PDF comes first — so
following it fetched a document rather than a list. It now prefers the
machine-readable form explicitly, and `pointersTo()` returns all of them. Of the
43 pointers in the current list, 11 are PDFs.

Test lists name their territory `EE_T` rather than `EE`, so a territory code is
validated as two letters with an optional suffix.

## 2026-09-12 — Phase 5, archive timestamps

### One word decided the whole construction

The octet stream an archive timestamp covers is built in five steps, and the
first one reads, in EN 319 132-1 clause 5.5.2.2, "take all the ds:Reference
elements ... referencing whatever the signer wants to sign **including the
SignedProperties element**".

That "including" is the opposite of the signature timestamp's own rule, and
leaving the SignedProperties reference out produces a stream that is entirely
plausible — right length, right order, right canonicalisation — and digests to
nothing. Four other guesses were tried first: inclusive canonicalisation
instead of exclusive, dropping `ds:KeyInfo`, putting the data objects last, and
including the archive timestamp in its own input. None matched, and none would
have been distinguishable from the real mistake by reasoning alone.

What settled it was reading the reference implementation. DSS's
`XAdESTimestampMessageDigestBuilder::getArchiveTimestampMessageDigest()` quotes
the clause in a comment directly above the loop that iterates every reference
without exception.

### The fixture is the specification

The digidoc4j LTA container in `tests/fixtures/containers` is the only reason
any of this can be trusted. `ArchiveTimestampDataTest` digests our stream and
compares it with the imprint digidoc4j's timestamp authority was actually asked
to stamp, and the two match to the byte. An archive timestamp has to be
verifiable years later by software nobody has written yet, so agreement with
another implementation is the only evidence worth having; our own tests
agreeing with our own encoder would prove nothing at all.

SiVa then reads a container we archive as `XAdES_BASELINE_LTA` and reports
TOTAL-PASSED, which closes the loop from the other side.

### Canonicalisation left unstated means inclusive

`ds:CanonicalizationMethod` inside an archive timestamp is optional, and XML-DSig's
default when it is absent is inclusive canonicalisation — not the exclusive form
that every Estonian signature actually uses. A validator that assumed exclusive
would reconstruct a different stream for such a signature and reject a perfectly
good timestamp. allkiri reads the declared algorithm and falls back to inclusive,
and always writes the element when producing one.

### A broken archive timestamp does not condemn the signature

An archive timestamp that fails to verify is reported as INDETERMINATE with
NO_POE rather than TOTAL-FAILED, and the signature beneath it is still judged on
its own merits. The distinction is real: the signature is valid today, and what
is missing is the protection it was supposed to have for tomorrow. The one
exception is an archive timestamp dated before something it covers, which is a
contradiction rather than a gap and is reported as a failure.

### Adding a constructor parameter in the middle breaks callers

`SigningService` gained `$ltaExtender` next to `$ltExtender`, where it belongs,
and every positional call passing a `SignatureBuilder` third then passed it as
the wrong parameter. PHPStan caught it because the types differ; had both been
nullable objects of compatible shape it would not have. Worth remembering for
anything after 1.0, where the fix cannot be "update the callers".

## 2026-09-12 — Phase 6, the browser half and the demo

### The page decides nothing

`assets/allkiri.js` moves bytes between the Web eID extension, your endpoints
and the screen. It never inspects a token, never looks at a certificate, and
never reports success on its own: every answer is posted to the server, which is
the only place a signature can be checked. This sounds obvious and is exactly
what a helper library is tempted to get wrong, because "show the person their
name from the certificate" is a two-line feature that quietly moves an
authentication decision into a page.

The one thing it does decide is that a missing extension is an error before the
server is asked for anything. A challenge issued to a browser that cannot answer
it leaves a session open for its whole lifetime for no reason.

### The QR encoder is vendored, not depended on

A Smart-ID device link needs a new QR code about once a second, and the obvious
answer — pull in a QR library — means an application that wants to sign
something now ships someone else's npm tree, or a CDN request, to draw a square.
`assets/allkiri-qr.js` is about 560 lines, byte mode only, levels L and M,
versions 1 to 20, which covers every link SK produces with room to spare.

### A QR code that scans is the only proof a QR encoder works

The first version produced codes that looked entirely plausible — right size,
right finder patterns, believable noise — and scanned as nothing at all. The
generator polynomial was being built reversed, so every error-correction
codeword was wrong while every structural byte was right.

Comparing against another encoder was initially misleading: `qrcode` chose
alphanumeric mode for the test string and ours chose byte mode, so the matrices
differed for a legitimate reason and the real difference hid behind it. What
settled it was checking the degree-7 polynomial against its published alpha
exponents, and then `tests/js/qr-roundtrip.mjs`: 1208 strings encoded here and
decoded by `jsqr`, at every length from 1 to 600, both levels, all eight masks.
The golden test pins six matrices by digest so a regression is caught without
`jsqr` installed; the round-trip test is what would have caught the original
mistake.

### The demo found a bug twelve tests could not

`AsicWriter` re-emits entries read from the original archive byte for byte,
which is what keeps other signatures valid when one is appended. Replacing a
signature file in place — what an archive timestamp does — left the stale entry
in that list, so the new XML was built, reported as added, and discarded at the
moment of writing.

Every test in `ArchiveTimestampTest` archived a container that had just been
built in memory, where `originalEntries` is empty and there is nothing to win.
The demo downloaded a container it had been told was LTA and got LT. The lesson
is not about ZIP entries: a test fixture that never travels through the
persistence layer cannot find a bug that lives there, however many assertions it
makes about the model.

### The demo is one file on purpose

`examples/demo-app/app.php` holds every endpoint, because the point of the demo
is to be read in one sitting by someone deciding whether this library fits their
application. A well-factored demo with a router, a container and six classes
demonstrates good structure and hides the two lines that matter. Anything a real
application must do differently — accounts, rate limiting, not echoing exception
messages at people — is said plainly in the README rather than implemented.

## 2026-09-13 — the Web eID validator's DER encoding

### One authentication in 256 was refused, and it was not ours

A CI run failed on one PHP version with "Token signature validation has failed".
Running the test two hundred times reproduced it three times, so it was a rare
value-dependent failure rather than a broken change.

The cause is in `web-eid/web-eid-authtoken-validation-php`. A card returns an
ECDSA signature as raw r‖s with each half padded to the width of the curve, so
about one half in 256 begins with a zero byte. `AsnUtil::transcodeSignatureToDER`
adds a leading zero when the first byte exceeds 0x7f, which is right, but never
removes one that is already there, and DER requires integers in minimal form.
OpenSSL refuses the result.

Measured over six thousand signatures from the same key, the split is exact:

| Leading zero followed by | Verified | Rejected |
|---|---|---|
| a byte above 0x7f (the zero is required) | 23 | 0 |
| a byte of 0x7f or less (the zero is superfluous) | 0 | 23 |
| no leading zero | 5954 | 0 |

Two halves, one in 256 chance each, half of those superfluous, gives one in 256
overall. The measured rate was 0.38 per cent.

### It had already been found, and looking first would have been cheaper

The first instinct was that a defect failing one login in 256 would have been
noticed by now. That instinct was right. Issue #71 on their repository, opened
2026-07-22, describes the same symptom from production: fails on the first try,
succeeds on the second. Pull request #74 fixes it. Neither had moved in six
weeks, and 1.3.1 is still the current release.

The lesson is not about ECDSA. Before claiming a defect in someone else's
library, read their issue tracker: it costs one search and it either saves the
report or tells you what the maintainers already think.

### The workaround, and how to know it can go

`WebEidAuthenticator::withDerSignature()` re-encodes the signature with our own
encoder before handing the token over. Their validator skips its own conversion
when the signature already looks like DER, so the broken path is never entered.
Only the encoding changes: the same r and s are verified against the same
certificate over the same bytes, so nothing refused before is accepted now.

`testASignatureWhoseHalfBeginsWithASuperfluousZeroIsAccepted` pins a real
signature whose s half begins 00 7B. It fails with the workaround removed and
passes with it, which is exactly the signal for deleting the workaround: when a
release contains the upstream fix, take the workaround out and that test should
stay green.

### What it says about the dependency

Keeping the official validator was argued on the grounds that authentication is
the one place where being wrong is expensive. That still holds, but it is now
tempered: the library is demonstrably wrong in the middle of what it exists to
do, its fix has sat unreleased for six weeks, and this project already reaches
past it for trust and revocation. The decision to replace it after 1.0 should be
weighed again with that on the record, and any replacement must be measured
against the Web eID project's own test vectors rather than against our reading of
the specification.

## 2026-09-15 — exceptions, stored sessions and the signing checks

### An interface at the root

`AllkiriException` was an abstract `RuntimeException`, and the library's
`InvalidArgumentException` extended it. So `catch (\InvalidArgumentException)`,
the usual way PHP code catches a wrong argument, missed it, and
`catch (\RuntimeException)` caught programmer errors along with failures at run
time. Two throws sat outside the family altogether: an anonymous exception class
that could not be caught by name, and a `\LogicException`.

`AllkiriException` is now an interface. Programmer and configuration errors throw
`Allkiri\Exception\InvalidArgumentException`, which extends SPL's; every other
exception extends `\RuntimeException` through its module's base class. Guzzle and
Symfony are built the same way, and `catch (AllkiriException)` keeps working. A
test walks `src` and fails on any exception outside the family, and on any SPL
exception or anonymous exception class created there.

### One exception for what was stored

A prepared signature, a session or a challenge is written to the application's
store in one request and read back in the next. When it came back malformed,
the seven restores failed seven ways: `InvalidArgumentException`, which calls it
a programmer error; PHP's `ValueError` or date exceptions; a
`CertificateException`; and, for a Web eID signing session, a `WebEidException`.
A Mobile-ID session whose challenge was not base64 was not refused at all.

They now share one reader, and every restore throws `SessionDataException`, a
runtime exception: the data came from the store rather than from the code, and
the useful response is to start again. What the reader finds wrong itself is
named by field, without the value. What an object refuses after the reader
accepted it, such as a phone number in no known form, is wrapped with the
original exception as `previous`, and so is PHP's `ValueError`.

A prepared signature whose XML no longer parses is not one of these. Code can
build a `DataToBeSigned` as well as restore one, so `finalize()` refuses it as a
`SessionMismatchException`: a prepared document that no longer holds together.

### Trust is checked before anything is spent

`finalize()` verified the signature value before buying a timestamp, but the
signer's certificate chain was first built after the timestamp had been bought,
and at level T not at all: an untrusted signer cost a timestamp, and at T was
given one. Timestamp failures and trusted lists that could not be loaded escaped
as their own exceptions, while chain and OCSP failures were wrapped.

`prepare()` now builds the chain at level T and above, before a person is asked
for a PIN or a Mobile-ID or Smart-ID session is started, and `finalize()` builds
it again before the timestamp, because the trust store can change between the
two requests. The check lives on `LtExtender`, which holds the chain builder, so
every signing service that can reach level T has it; an optional chain builder
is how the Mobile-ID and Smart-ID authenticators once skipped their trust check.
Every failure of what a signature needs now arrives as a `SigningException` with
the original as `previous`.

In production this moves the first loading of the trusted lists from the first
`finalize()` to the first `prepare()`.

### A prepared signature expires

`DataToBeSigned` carried `createdAt`, and `finalize()` never read it: a session
left in a store for days could still be finished and timestamped today. SK ends
a Mobile-ID or Smart-ID session after two minutes, but card signing had no limit
at all.

`finalize()` now refuses a signature prepared more than ten minutes earlier,
before anything is bought, with `PreparedSignatureExpiredException`. Ten minutes
leaves room for a slow person and for clocks that differ a little between
servers. The age is measured from the signing time inside the signature, not
from `createdAt`: the signature has just verified, so its signing time is what
was signed, while `createdAt` is only stored beside it. For the same reason a
signing time more than five minutes ahead of the server's clock is refused, the
skew OCSP and validation already allow; otherwise preparing on a clock set ahead
would stretch the limit. The limit is `preparedSignatureTtlSeconds` on the
`Allkiri` constructor, and on `SigningService` for applications that build their
own.

### Configured URLs versus URLs from data

A URL the application configures that is not http(s), such as an OCSP override or
a trusted-list source, is a programmer error and stays an
`InvalidArgumentException`. A URL that comes from data is not one: a certificate
names its OCSP responder, and the list of trusted lists names where a national
list lives. An address at another scheme there reached the HTTP client and
escaped as `InvalidArgumentException`, from code that promised `OcspException` or
`TrustedListException`. The OCSP client now skips an address that is not http(s)
and falls back to the default responder, and a list-of-lists pointer to such a
location is refused with `TrustedListException`.
