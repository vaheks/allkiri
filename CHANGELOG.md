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

### Verified against

- Containers made by digidoc4j, including one that validates TOTAL-PASSED end
  to end once its PKI is trusted.
- The live Estonian test trusted list, SK's demo timestamp and OCSP services,
  and SiVa.

### Not yet

Mobile-ID, Smart-ID and Web eID; archive timestamps (LTA); BDOC-TM
(time-mark) signatures, which SK stopped supporting on 2023-11-01 and which
this library reports as unsupported rather than validating.
