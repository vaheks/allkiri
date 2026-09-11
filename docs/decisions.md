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
