# Certificates that may sign the EU list of trusted lists

These six certificates are the root of production trust. Everything else —
which national lists exist, where they live, which certificates sign them, and
which services each one publishes — is read from the list of lists itself and
needs no release of this library.

## Where they come from

Published by the European Commission in the Official Journal, which is the
authoritative source and the only one. The list of lists names its own
publication in a `SchemeInformationURI`, so the reference can be followed from
the list back to the Journal rather than taken on faith.

| | |
|---|---|
| Publication | C/2026/1944, 15 April 2026 |
| Title | Information related to data on Member States' trusted lists as notified under Commission Implementing Decision (EU) 2015/1505 as amended by Commission Implementing Decision (EU) 2025/2164 |
| URL | <https://eur-lex.europa.eu/eli/C/2026/1944/oj> |
| Captured | 12 September 2026, against list-of-lists sequence number 393 |

## What is here

| File | SHA-256 of the certificate | Subject |
|---|---|---|
| `lotl-signer-1.pem` | `c0641c4f7d56c431b1c924742db7fce9c1eef7d7fd212113a2768486b3abcdc5` | IOANNA KALOGEROPOULOU, European Commission |
| `lotl-signer-2.pem` | `e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1` | European Commission, DG for Digital Services (DIGIT) |
| `lotl-signer-3.pem` | `df7e29360c34b2b8d6d5f40325c1d4d12c9922cecd33b7407674a74b2b3ca1e5` | VICENTE ANDREU NAVARRO, European Commission |
| `lotl-signer-4.pem` | `b63d416744e7098bf9ec2caa596a93bc2468e37f8284ba65ecc061711bcbaa18` | APOSTOLOS APLADAS, European Commission |
| `lotl-signer-5.pem` | `236103f03a8031ae8f47f9059bf8de38564cdbfebedde4a597d50f8980aa653b` | European Commission, DG for Digital Services (EU-TRUST) |
| `lotl-signer-6.pem` | `d2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474` | Patrick Kremer |

The live list of lists at sequence 393 was signed with `lotl-signer-2.pem`, and
that signature verifies with allkiri's own verifier. The others are the rest of
the set the Journal publishes, any of which may sign a future issue.

## Verify them yourself before trusting production to them

These certificates decide what your application will accept as a qualified
signature. Shipping them in a library is a convenience, not an assurance:
check them against the Journal rather than against this file.

```bash
openssl x509 -in resources/trust/eu/lotl-signer-2.pem -outform DER \
  | openssl dgst -sha256
```

Compare the result with the digest printed beside that certificate in the
publication linked above. The Journal prints both SHA-256 and SHA-1 digests for
each certificate, in hexadecimal and base64.

## Keeping them current

The set changes when the Commission publishes a new decision, which the list of
lists then points to. `tests/Integration/ListOfListsLiveTest.php` fetches the
live list and fails if it is signed by something not in this directory, so a
nightly run is the warning that these need refreshing.

To refresh: read the `SchemeInformationURI` values in the current list of lists,
open the Journal publication they name, and replace these files with the
certificates it publishes, updating the table above.
