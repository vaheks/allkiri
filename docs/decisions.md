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

### Tooling

- The shell transport truncates commands above roughly 8 KB, which surfaces
  as `unexpected EOF while looking for matching quote`. Files longer than a
  couple of kilobytes are written with the editor tool, not heredocs.
- OpenSSL 3.5 CLI is available locally and used as the independent
  cross-check (`openssl ts`, `openssl ocsp`, `openssl asn1parse`).
