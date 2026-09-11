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

## From DigiDoc4 (to be added)

Containers signed in DigiDoc4 test mode with a test Mobile-ID number and a
Smart-ID demo account belong here too. They are the reverse-interop evidence
for RIA's own client.
