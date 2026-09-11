# Testing

```bash
composer check   # coding standard, static analysis, unit tests
```

Everything runs offline. No eID hardware, no accounts, no network.

## How that is possible

`tests/fixtures/pki` holds a committed test PKI: a CA, three signers (ECDSA
P-256 and P-384, RSA), a timestamp authority and an OCSP responder, all valid
2020 to 2050 so no test ever expires. `tests/fixtures/pki/generate.sh`
regenerates them; running it invalidates every golden file, so only do it
deliberately.

`tests/Support/Pki` adds an in-process timestamp authority and OCSP responder
that speak the real protocols, with knobs for every way they could go wrong:
a wrong nonce, a missing certificate, a corrupt signature, a response produced
in the future, a revoked or unknown certificate. `SigningFixture` wires them
together, so a full XAdES-LT signature is built and verified in a unit test.

## Fixtures from other implementations

`tests/fixtures/containers` holds containers made by digidoc4j, signed with
SK's test certificates. They are the reverse-interop evidence: our verifier
must accept what the rest of the ecosystem produces. One of them validates
TOTAL-PASSED end to end once its PKI is trusted.

`tests/fixtures/captured` holds real responses from the demo services, so the
ASN.1 layer is tested against what SK actually sends rather than against our
own encoder.

## Integration tests

```bash
ALLKIRI_INTEGRATION=1 composer test:integration
```

These talk to the free demo services: SK's timestamp and validity confirmation
services, RIA's test trusted list, and SiVa. They run nightly in CI, never on
a pull request, because a shared service being slow must not fail someone's
change.

| Variable | For |
|---|---|
| `ALLKIRI_CA_BUNDLE` | a PEM file of certificate authorities, when PHP has no `curl.cainfo` configured (common on Windows, where every HTTPS call otherwise fails with curl error 60) |
| `ALLKIRI_TEST_P12` | a PKCS#12 whose CA is in the Estonian test trusted list; turns the SiVa gate into a full TOTAL-PASSED |
| `ALLKIRI_TEST_P12_PASSWORD` | its password |

Two tests skip with instructions until a certificate is available:

- Signing with our own test key needs `tests/fixtures/pki/signer-rsa.cert.pem`
  uploaded at <https://demo.sk.ee/upload_cert/> with status "Good", so the demo
  responder will answer for it.
- The full SiVa gate needs `ALLKIRI_TEST_P12`. SK issues test certificates free
  of charge; ask at <info@skidsolutions.eu>.

## Writing tests

Unit tests must stay offline and deterministic. Use `FrozenClock` for time and
`FixedNonceGenerator` where output has to be reproducible. Note that an LT
signature can never be byte-reproducible: a timestamp token and an OCSP
response are fresh every time.

Only test material may be committed. Never a container signed with a real
person's certificate, never a production relying-party identifier, never a
private key that is not a throwaway.
