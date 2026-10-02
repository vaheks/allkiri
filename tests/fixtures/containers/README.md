# Container fixtures

Signed containers produced by other implementations, used to prove that
allkiri validates what the rest of the ecosystem creates.

## From digidoc4j

Taken from
`digidoc4j/src/test/resources/testFiles/valid-containers` of
[open-eid/digidoc4j](https://github.com/open-eid/digidoc4j) (LGPL-2.1,
Estonian Information System Authority). They are test data, signed with SK's
**test** certificates; no real person's certificate is involved.

| File | What it exercises |
|---|---|
| `valid-asice-esteid2018.asice` | XAdES-LT, ECDSA P-384 (`ecdsa-sha384`), TEST of ESTEID2018 signer, full CertificateValues |
| `valid-asice.asice` | XAdES-LT, RSA 2048 (`rsa-sha256`), TEST of ESTEID-SK 2015 signer |
| `valid-asice-lta.asice` | XAdES-LTA: an archive timestamp on top of LT, signatures file named `signatures1.xml` |
| `EE_LT_sig_OCSP_15m6s_after_TS.asice` | OCSP produced 15 minutes 6 seconds after the timestamp: the warning threshold |
| `NoAdditionalCertificates_LT.asice` | LT without `CertificateValues`: only `RevocationValues` |
| `2_signatures_duplicate_id.asice` | Two signature files whose `ds:Signature` share one `Id` |

## From libdigidocpp

libdigidocpp is the library inside DigiDoc4, and it signs with C14N 1.1
(`xml-c14n11`), where digidoc4j and allkiri use exclusive C14N. Taken from
`test/data` of [open-eid/libdigidocpp](https://github.com/open-eid/libdigidocpp)
(LGPL-2.1, Estonian Information System Authority), at the commits named below.
Test data, signed with test certificates; no real person's certificate is
involved.

| File | Upstream | What it exercises |
|---|---|---|
| `libdigidocpp-c14n11-2016.asice` | `test/data/tsl.asice` at `6adf6fd` | C14N 1.1 throughout, RSA (`rsa-sha256`), the test person MÄNNIK, MARI-LIIS under TEST of ESTEID-SK 2011 |
| `libdigidocpp-c14n11-2013.asice` | `test/data/test.asice` at `9ebb330` | C14N 1.1, RSA, signed under libdigidocpp's own test CA |

Their certificates expired long ago and their CAs are on no list allkiri
trusts, so they are verified as XML signatures, byte for byte, rather than
validated for trust. DigiDoc4 4.11 output itself, which they stand in for, was
validated TOTAL-PASSED on 2026-10-02 from the author's own containers, which
cannot be committed because they carry a real person's certificate.

## From DigiDoc4

The DigiDoc4 beta that trusts test certificates can no longer sign (see
`docs/manual-testing.md`), so no container DigiDoc4 signed with a test
Mobile-ID or Smart-ID demo account can be made for this directory any more.
