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
  behind every eID mean here are reached through it.

### Not yet

The ID card against real hardware, which needs a card, a reader and a person;
Smart-ID device-link flows against a live service, which needs someone to scan
a code; archive timestamps (LTA); BDOC-TM
(time-mark) signatures, which SK stopped supporting on 2023-11-01 and which
this library reports as unsupported rather than validating.
