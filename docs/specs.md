# Specifications, services and references

Everything `allkiri` is built against, verified on 2026-09-12. When one of
these moves, update this file in the same change.

## Signature format

| What | Where |
|---|---|
| BDOC 2.1.2, the Estonian ASiC-E / XAdES profile | https://www.id.ee/wp-content/uploads/2021/06/bdoc-spec212-eng.pdf |
| BDOC / ASiC-E overview and lifecycle | https://www.id.ee/en/article/bdoc-cdoc-and-asice-digidoc-file-formats-2/ |
| ETSI EN 319 132-1, XAdES building blocks and baseline signatures | https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/ |
| ETSI EN 319 162-1, ASiC building blocks and baseline containers | https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/ |
| XML Signature Syntax and Processing 1.1 | https://www.w3.org/TR/xmldsig-core1/ |
| Exclusive XML Canonicalization | https://www.w3.org/TR/xml-exc-c14n/ |
| RFC 6931, additional XML-DSig algorithm URIs (RSA-PSS with MGF1, ECDSA-SHA*) | https://www.rfc-editor.org/rfc/rfc6931 |
| RFC 3161, Time-Stamp Protocol | https://www.rfc-editor.org/rfc/rfc3161 |
| RFC 6960, OCSP | https://www.rfc-editor.org/rfc/rfc6960 |
| Cryptographic algorithm lifecycle reports (RIA) | https://www.id.ee/en/article/cryptographic-algorithms-life-cycle-reports-2/ |

Profile decisions: XAdES Baseline **LT** (timestamp first, then OCSP), optional
**LTA**; BDOC-TM (time-mark) is not implemented because SK stopped supporting it
on 2023-11-01.

## ID-card and Web eID

| What | Where |
|---|---|
| Web eID system architecture (auth and signing flows) | https://github.com/web-eid/web-eid-system-architecture-doc |
| web-eid.js browser library | https://github.com/web-eid/web-eid.js |
| Auth-token validation library for PHP (dependency) | https://github.com/web-eid/web-eid-authtoken-validation-php |
| Thales cards, PHP configuration notes | https://github.com/web-eid/web-eid-authtoken-validation-php/wiki/New-Thales-ID-Cards-in-Estonia-2025 |
| Web eID mandatory by end of 2026 | https://www.id.ee/en/article/e-services-must-switch-to-the-web-eid-solution-by-the-end-of-2026/ |
| Thales ID-card (Zetes PKI) developer notes | https://www.id.ee/en/article/thales-id-card/ |
| Zetes CA certificates (production) | https://repository.eidpki.ee/crt/ |
| Zetes test chain | https://crt-test.eidpki.ee/testEEGovCA2025.crt and https://crt-test.eidpki.ee/testESTEID2025.crt |
| Zetes OCSP | production `http://ocsp.eidpki.ee/`, test `http://ocsp-test.eidpki.ee` |
| SK OCSP (IDEMIA cards, Mobile-ID, Smart-ID) | https://github.com/SK-EID/ocsp/wiki ; AIA `http://aia.sk.ee/...`, demo `http://aia.demo.sk.ee/...`, contract `http://ocsp.sk.ee`, demo `http://demo.sk.ee/ocsp` |
| Web eID demo site | https://web-eid.eu/ |

## Mobile-ID

| What | Where |
|---|---|
| REST API specification | https://github.com/SK-EID/MID |
| Test numbers and outcomes in DEMO | https://github.com/SK-EID/MID/wiki/Test-number-for-automated-testing-in-DEMO |
| Base URLs | demo `https://tsp.demo.sk.ee/mid-api`, production `https://mid.sk.ee/mid-api` |
| Demo relying party | UUID `00000000-0000-0000-0000-000000000000`, name `DEMO` |
| Secure implementation guide | https://github.com/SK-EID/MID/wiki/Secure-Implementation-Guide |
| Environment technical parameters | https://github.com/SK-EID/MID/wiki/Environment-technical-parameters |
| Official PHP client (authentication only, reference) | https://github.com/SK-EID/mid-rest-php-client |

Endpoints: `POST /certificate`, `POST /authentication`, `POST /signature`, and
`GET /{authentication|signature}/session/{id}?timeoutMs=` for long polling
(default 10 000 ms, larger values silently reduced to the service maximum).
Hash types `SHA256`, `SHA384`, `SHA512`; languages `EST`, `ENG`, `RUS`, `LIT`.
Display text: 100 characters in `GSM-7` with at most 5 from the extension
table, or 50 in `UCS-2`; characters outside `GSM-7` are replaced with spaces
rather than refused. The verification code is 6 bits from the start of the
hash and 7 from its end, read as four decimal digits.

## Smart-ID

| What | Where |
|---|---|
| RP API v3 documentation root | https://sk-eid.github.io/smart-id-documentation/ |
| Endpoints overview | https://sk-eid.github.io/smart-id-documentation/rp-api/overview_of_api_endpoints.html |
| Signature protocols (ACSP_V2, RAW_DIGEST_SIGNATURE) | https://sk-eid.github.io/smart-id-documentation/rp-api/signature_protocols.html |
| Environments, base URLs, pinning | https://sk-eid.github.io/smart-id-documentation/environments.html |
| Test accounts | https://sk-eid.github.io/smart-id-documentation/test_accounts.html |
| Base URLs | demo `https://sid.demo.sk.ee/smart-id-rp/v3/`, production `https://rp-api.smart-id.com/v3/` |
| Scheme names | demo `smart-id-demo`, production `smart-id` (part of every signed payload and device link) |
| Demo relying party | UUID `00000000-0000-4000-8000-000000000000`, name `DEMO` |
| Official Java client (reference for ACSP_V2 validation and device links) | https://github.com/SK-EID/smart-id-java-client |
| Official PHP client (authentication only, PHP 8.4, reference) | https://github.com/SK-EID/smart-id-php-client |

The RP API reference pages are rendered from a module that is not in the public
documentation repository, so the wire format here was read from the two clients
above and confirmed against the live demo service.

Endpoints (relative to the base URL): `POST /signature/certificate/{documentNumber}`;
`POST /signature/certificate-choice/notification/etsi/{identifier}`;
`POST /{authentication|signature}/notification/{etsi|document}/{id}`;
`POST /{authentication|signature}/device-link/{anonymous|etsi|document}[/{id}]`;
`GET /session/{id}?timeoutMs=`.

Protocols: `ACSP_V2` for authentication, `RAW_DIGEST_SIGNATURE` for signing, both
with `rsassa-pss` (MGF1 over the same hash, salt = digest length, trailer
`0xbc`). Certificate levels `ADVANCED`, `QUALIFIED`, `QSCD`. Interactions
`displayTextAndPIN` (60 characters), `confirmationMessage` and
`confirmationMessageAndVerificationCodeChoice` (200), sent base64-encoded as a
JSON array. A notification authentication must send `vcType: numeric4` and gets
no code back; a notification signature sends none and gets `vc` back. The
verification code is the last two bytes of the SHA-256 of the challenge or
digest, read as an unsigned 16-bit big-endian number, modulo 10000.

## Timestamping

| What | Where |
|---|---|
| SK timestamping technical information | https://github.com/SK-EID/Timestamping/wiki/Timestamping-Service-Technical-Information |
| Endpoints | demo `http://tsa.demo.sk.ee/tsa` (free), production `http://tsa.sk.ee` (contract) |

## Trust lists

| What | Where |
|---|---|
| EU List of Trusted Lists | https://ec.europa.eu/tools/lotl/eu-lotl.xml |
| Estonian trusted list | https://sr.riik.ee/tsl/estonian-tsl.xml |
| Test LOTL and test Estonian TL | https://open-eid.github.io/test-TL/tl-mp-test-EE.xml and https://open-eid.github.io/test-TL/EE_T.xml |
| TL v6 transition and LOTL anchor change (2026) | https://www.id.ee/en/article/the-planned-start-of-the-transition-period-to-version-6-of-the-trusted-list-is-14-april-2026-in-addition-the-lotl-trust-anchors-will-change/ |
| Using TSLs in software libraries | https://www.id.ee/en/article/using-certificate-trust-service-status-lists-tsls-in-software-libraries-2/ |

## Validation

| What | Where |
|---|---|
| SiVa documentation | https://open-eid.github.io/SiVa/ |
| SiVa endpoints | demo `https://siva-demo.eesti.ee/V3/`, production `https://siva.eesti.ee/V3/` |
| RIA digital signature services (SiVa, SiGa) | https://www.ria.ee/en/state-information-system/electronic-identity-eid-and-trust-services/services-digital-signatures |

## Testing

| What | Where |
|---|---|
| id.ee testing overview (test cards, demo services) | https://www.id.ee/en/article/service-testing-general-information/ |
| Thales test cards | Police and Border Guard Board, or https://shophansab.ee/toode/test-id-card-thales/ |
| DigiDoc4 with test certificates | https://www.id.ee/en/article/digidoc4-client-digital-signing-and-signature-validation-with-a-test-id-card-mobile-id-and-smart-id/ |

## Reference implementations

| What | Where |
|---|---|
| digidoc4j (Java) | https://github.com/open-eid/digidoc4j |
| libdigidocpp (C++) | https://github.com/open-eid/libdigidocpp |
| SiGa, signature gateway (Java, self-hostable) | https://github.com/open-eid/SiGa |
| undersign.js (JavaScript, LGPL) | https://github.com/moll/js-undersign |
| pyasice (Python) | https://github.com/thorgate/pyasice |
| php-asic-e (PHP, MIT) | https://github.com/vatsake/php-asic-e |
| id.ee developer hub | https://www.id.ee/en/rubriik/for-developer/ |
