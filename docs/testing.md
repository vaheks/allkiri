# Testing

```bash
composer check   # coding standard, static analysis, unit tests
```

Everything runs offline. No eID hardware, no accounts, no network.

A few HTTP client tests need a real socket, to see what cURL does with an
answer that is too large. `tests/Support/Http/LocalHttpServer` starts PHP's
built-in web server for them on 127.0.0.1, on a port the operating system
picks, and stops it when the test class is done. That is still offline: nothing
leaves the machine.

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

## Coverage

```bash
composer test:coverage
```

Line coverage of the unit suite, written to `coverage/`: `summary.txt`,
`clover.xml` for tools, and an HTML report in `coverage/html/`. It needs pcov,
or Xdebug with `XDEBUG_MODE=coverage`. Without either, PHPUnit warns that no
coverage driver is available, and because warnings fail this suite, the run
fails too.

CI measures it on every push and pull request, in a job of its own on PHP 8.4
with pcov. The summary is on the run's page, and the reports are kept as the
`coverage` artifact for 14 days. Nothing fails on a percentage.

Two things the number leaves out. `DemoAppTest` runs the demo application in a
PHP process of its own, so library code a request reaches there is not counted.
The integration suite is not measured at all.

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
| `ALLKIRI_TEST_P12` | a PKCS#12 whose CA is in the Estonian test trusted list; turns the local-key SiVa gate into a full TOTAL-PASSED. Optional: the Mobile-ID demo test already reaches TOTAL-PASSED with a key the test trusted list covers |
| `ALLKIRI_TEST_P12_PASSWORD` | its password |
| `ALLKIRI_ARTEFACTS` | a directory to keep the containers the Mobile-ID demo test signs, for opening in DigiDoc4 |
| `ALLKIRI_MID_URL`, `ALLKIRI_MID_RP_UUID`, `ALLKIRI_MID_RP_NAME` | Mobile-ID endpoint and relying party; default to the public demo values |
| `ALLKIRI_SMARTID_URL`, `ALLKIRI_SMARTID_RP_UUID`, `ALLKIRI_SMARTID_RP_NAME` | the same for Smart-ID |

SiVa sits behind Cloudflare, which now and then answers a CI runner with a
challenge page instead of a verdict. The tests ask SiVa through
`IntegrationTestCase::askSiva()`, which waits ten seconds and asks once more,
then skips the rest of the test with the reason. Whatever the test checked
before asking SiVa has already passed or failed. The workflow prints the reasons
for skipped tests, so look there when the SiVa checks stop running.

`ListOfListsLiveTest` needs no configuration and is the one that matters most
nightly, because `resources/trust/eu` can only be refreshed by hand. It fails
when the European list of trusted lists names signing certificates this
library does not ship, which is the first sign of a change; when it names an
Official Journal publication other than the one in
`resources/trust/eu/README.md`, which means the new set is published; and when
it is signed by a certificate this library does not ship, which means
production trust no longer loads. The README says how to refresh.

`BundledCertificatesTest` fails when a certificate under `resources/trust`
expires within 90 days, and says where its replacement comes from. Nothing in
the library checks those dates, because a trusted list is accepted when its
signer matches one of them byte for byte. It is an integration test only
because its outcome depends on the day it runs.

### The test signing key and the demo OCSP service

`tests/fixtures/pki/signer-rsa.cert.pem` has been uploaded at
<https://demo.sk.ee/upload_cert/>, so `http://demo.sk.ee/ocsp` answers for it
and an LT signature can be completed with it. Re-upload it if the fixtures are
ever regenerated.

Two peculiarities of that service, both handled in the test rather than in the
library (see [decisions.md](decisions.md)): the answer is signed by a shared
responder that our test CA did not issue, so the responder has to be named
explicitly as a trusted responder; and the test certificate's own AIA points at
a URL that does not resolve, so the demo responder is configured for its issuer.

### The last skipping test

The full SiVa gate needs `ALLKIRI_TEST_P12`: a key whose CA is in the Estonian
test trusted list, which turns SiVa's verdict from "the format is fine but the
CA is unknown" into a clean TOTAL-PASSED. SK issues test certificates free of
charge; ask at <info@skidsolutions.eu>. `MobileIdDemoTest` provides the same
evidence for nothing, because Mobile-ID's demo numbers sign with certificates
from a CA the test trusted list already names.

## The production smoke test

`composer test:live` is a release gate rather than a test anyone runs
routinely, so [releasing.md](releasing.md) describes it. One thing about it
belongs here: it reads its settings through `examples/demo-app/config.php`, the
demo application's configuration, not through a reader of its own.

That is deliberate. Live mode's rules are written in that file: the mode is one
explicit word, and live mode refuses to start without every credential it
needs. A second copy in the test suite could drift from the one a person
actually runs, and the smoke test would then prove a rule the demo does not
enforce. The price is a test that depends on an example: moving that file, or
changing `Config::fromEnvironment()`, breaks the smoke test. PHPStan analyses
both, so the next `composer check` reports it.

## Writing tests

Unit tests must stay offline and deterministic. Use `FrozenClock` for time and
`FixedNonceGenerator` where output has to be reproducible. Note that an LT
signature can never be byte-reproducible: a timestamp token and an OCSP
response are fresh every time.

Only test material may be committed. Never a container signed with a real
person's certificate, never a production relying-party identifier, never a
private key that is not a throwaway.
