# Manual testing

Some things only a person with the software installed can check. This is the
list, and the record of when it was last done.

## Why these are not automated

DigiDoc4 is a desktop application. Nothing in CI can open a container in it,
and no automated check substitutes for seeing RIA's own client accept a
signature allkiri made.

## Setting up DigiDoc4 for the test environment

The released DigiDoc4 will not trust test certificates. Use the beta build,
which reads the test trusted list:

- Windows: <https://installer.id.ee/media/id2019/Windows/>
- macOS: <https://installer.id.ee/media/id2019/macOS/>
- Linux: <https://installer.id.ee/media/id2019/Ubuntu/>

The command-line tool shipped with it can be pointed at the test list
directly, which is the quickest check:

```bash
digidoc-tool open \
  --tslurl=https://open-eid.github.io/test-TL/tl-mp-test-EE.xml \
  --tslcert=trusted-test-tsl.crt \
  leping.asice
```

`trusted-test-tsl.crt` is at
<https://open-eid.github.io/test-TL/trusted-test-tsl.crt>, and the same
certificate is bundled here as `resources/trust/test/test-tsl-signer.pem`.

## The checklist

Produce the containers with the integration suite or a short script, then:

| # | Check | Last done | Result |
|---|---|---|---|
| 1 | An LT container allkiri signed with an RSA key opens in DigiDoc4 without warnings | | |
| 2 | The same with an ECDSA P-256 key | | |
| 3 | The same with an ECDSA P-384 key, the algorithm Estonian ID-cards use | | |
| 4 | The same with RSA-PSS, the algorithm Smart-ID requires | | |
| 5 | DigiDoc4 shows the signer's name and the signing time as expected | | |
| 6 | A second signature added **in DigiDoc4** to an allkiri container; both then validate in allkiri | | |
| 7 | A container DigiDoc4 created, signed with test Mobile-ID, validates in allkiri | | |
| 8 | The same with a Smart-ID demo account | | |
| 9 | A container allkiri appended a signature to still shows the original signature as valid | | |
| 10 | A container allkiri signed with **test Mobile-ID** opens in DigiDoc4 and shows the signature as valid | | |
| 11 | A container allkiri signed with **demo Smart-ID** (RSA-PSS) opens in DigiDoc4 and shows the signature as valid | | |

Items 7 and 8 also produce fixtures worth keeping: drop them into
`tests/fixtures/containers` and note in that directory's README how they were
made.

Item 10 is the most informative of them, because it is the only one signed with
a certificate DigiDoc4 already trusts in test mode, so a complaint there is
about what allkiri produced and nothing else. Produce it with:

```bash
ALLKIRI_INTEGRATION=1 ALLKIRI_ARTEFACTS=/some/directory \
  vendor/bin/phpunit tests/Integration/MobileIdDemoTest.php \
  --filter testAContainerSignedByADemoNumberIsAcceptedEverywhere
```

That writes `mobile-id-60001019906.asice` (ECDSA P-256) and
`mobile-id-39901019992.asice` (RSA) into that directory. Both are already
TOTAL-PASSED in SiVa, so DigiDoc4 should show them as valid signatures by
"O'CONNEŽ-ŠUSLIK TESTNUMBER,MARY ÄNN".

Item 11 is the one open cryptographic question in the project. RSA-PSS is the
only algorithm SK still recommends for Smart-ID, and some DigiDoc4 builds have
been reported to reject the `…#sha256-rsa-MGF1` signature method. SiVa accepts
our PSS containers, so if DigiDoc4 does not, that is a client limitation to
document rather than a defect to fix. Produce them with:

```bash
ALLKIRI_INTEGRATION=1 ALLKIRI_ARTEFACTS=/some/directory   vendor/bin/phpunit tests/Integration/SmartIdDemoTest.php   --filter testAnRsaPssContainerIsAcceptedEverywhere
```

Check both the SHA-256 and the SHA-512 file, and record which DigiDoc4 version
was used.

## Signing in DigiDoc4 test mode

Test Mobile-ID numbers are published at
<https://github.com/SK-EID/MID/wiki/Test-number-for-automated-testing-in-DEMO>;
`+37200000766` with personal code `60001019906` is the usual one. Smart-ID demo
accounts are at <https://sk-eid.github.io/smart-id-documentation/test_accounts.html>.

## When something fails

Record what DigiDoc4 said, keep the container, and open an issue with both.
A container that DigiDoc4 rejects and allkiri accepts is the most valuable
bug report this project can get.
