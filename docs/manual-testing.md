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
"C:/Program Files/DigiDoc4 Client/digidoc-tool.exe" open --tslurl=https://open-eid.github.io/test-TL/tl-mp-test-EE.xml --tslcert=C:/path/to/allkiri/resources/trust/test/test-tsl-signer.pem leping.asice
```

Both paths are absolute on purpose. `--tslcert` is resolved against the current
directory, not against the executable, and a relative name fails with a message
about opening an X.509 file. The certificate is bundled here as
`resources/trust/test/test-tsl-signer.pem`, byte for byte what RIA publishes as
`trusted-test-tsl.crt` at <https://open-eid.github.io/test-TL/trusted-test-tsl.crt>.

**The first run prints two errors and the second does not.** libdigidocpp tries
its cached copy of each trusted list before downloading, and reports every
failure of that attempt, including the file not being there yet, as
`TSL ... signature is invalid`. It then downloads the list, verifies it properly
and carries on. Run the command twice before believing the message.

## The checklist

Produce the containers with the integration suite or a short script, then:

| # | Check | Last done | Result |
|---|---|---|---|
| 1 | An LT container allkiri signed with an RSA key opens in DigiDoc4 without warnings | | |
| 2 | The same with an ECDSA P-256 key | 2026-09-18 | Valid — test Mobile-ID `60001019906`, whose ECC certificate is the one used |
| 3 | The same with an ECDSA P-384 key, the algorithm Estonian ID-cards use | 2026-09-18 | Valid — the card signature of item 14 |
| 4 | The same with RSA-PSS, the algorithm Smart-ID requires | 2026-09-18 | Valid — the Smart-ID signature of item 11 |
| 5 | DigiDoc4 shows the signer's name and the signing time as expected | 2026-09-18 | As expected |
| 6 | A second signature added **in DigiDoc4** to an allkiri container; both then validate in allkiri | | |
| 7 | A container DigiDoc4 created, signed with test Mobile-ID, validates in allkiri | | |
| 8 | The same with a Smart-ID demo account | | |
| 9 | A container allkiri appended a signature to still shows the original signature as valid | | |
| 10 | A container allkiri signed with **test Mobile-ID** opens in DigiDoc4 and shows the signature as valid | 2026-09-18 | Valid — in the beta with test Mobile-ID, and in 4.11.1.5434 with live |
| 11 | A container allkiri signed with **demo Smart-ID** (RSA-PSS) opens in DigiDoc4 and shows the signature as valid | 2026-09-18 | Valid — in the beta with demo Smart-ID, and in 4.11.1.5434 with live. See below |
| 12 | Signing in with a **test ID card** through Web eID, on an IDEMIA card | 2026-09-18 | Signed in — with a live IDEMIA card; no test card is available |
| 13 | The same on a Thales card issued since November 2025 | | |
| 14 | Signing a container with a test ID card; the result validates in allkiri and in SiVa | 2026-09-18 | Valid in DigiDoc4 and in allkiri, with a live card. SiVa not checked |
| 15 | The same in Chrome, Firefox and Safari | 2026-09-18 | Chrome only |
| 16 | An **XAdES-LTA** container allkiri archived opens in DigiDoc4 and shows the signature as valid | | |

### The round of 2026-09-18

Two rounds through the demo application, by the author and by several other
testers. Everything was in Chrome.

**The test environment first.** Test Mobile-ID and demo Smart-ID signed
containers, and those containers opened in the **DigiDoc4 beta** build, the one
that reads the test trusted list, and showed as valid. That is items 10 and 11
as they are written.

**Then production**, at the demo application's live deployment: the real
certificates, the real trusted list and the paid timestamp service, with
containers opened in the **released DigiDoc4 4.11.1.5434**. Every means was
exercised, the ID card included, and every signature showed as valid. That is
stronger than the rows ask for in the material it used, and it is not what the
rows say, so it is written down as itself.

| | |
|---|---|
| DigiDoc4 | beta for the test round; 4.11.1.5434 released for the production round |
| Browser | Chrome |
| Card | issued September 2025, so IDEMIA — Thales cards begin in November 2025 |

**Item 11 is answered, and it is the answer we wanted.** Both builds accept an
RSA-PSS signature allkiri produced: the `…#sha256-rsa-MGF1` signature method
some builds were reported to reject is shown as valid, in the beta against a
demo Smart-ID signature and in 4.11.1.5434 against a live one. Whether older
builds still refuse it is not established here, and a relying party supporting
them should check for itself.

**There is no test ID card here**, and one cannot be had casually, so items 12
to 15 cannot be done in the test environment at all. The production round with
a real card is the substitute, and it is why item 12 is answered with a live
IDEMIA card rather than a test one. A Thales card, item 13, is untested in
either environment.

The test Mobile-ID number was `60001019906`, whose ECC certificate is the one
the service uses, so that round also answers item 2. Item 1 wants RSA, which on
Mobile-ID means the single-RSA pair the integration suite reaches with
`+37200001566`.

Still open after this round: item 1, an RSA signature; items 6 to 9, which need
DigiDoc4 to create or add a signature rather than only read one; a Thales card
(13); the browsers other than Chrome (15); and an archived LTA container (16),
which the demo application can produce with its archive button.

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

Item 11 was the one open cryptographic question in the project, and as of
2026-09-18 it has an answer. RSA-PSS is the only algorithm SK still recommends
for Smart-ID, and some DigiDoc4 builds had been reported to reject the
`…#sha256-rsa-MGF1` signature method. **DigiDoc4 4.11.1.5434 does not reject
it**: a PSS signature allkiri made shows as valid. SiVa accepts them too.

That settles the build that matters today and says nothing about older ones, so
a relying party that has to support one should check rather than assume; a build
that does refuse is a client limitation to document rather than a defect to fix
here. The 2026-09-18 round covered SHA-256 only, which is what the library
chooses by default. Produce them with:

```bash
ALLKIRI_INTEGRATION=1 ALLKIRI_ARTEFACTS=/some/directory \
  vendor/bin/phpunit tests/Integration/SmartIdDemoTest.php \
  --filter testAnRsaPssContainerIsAcceptedEverywhere
```

Check both the SHA-256 and the SHA-512 file, and record which DigiDoc4 version
was used.

Item 16 covers the construction most likely to differ between
implementations. The octet stream an archive timestamp covers is intricate, and
a wrong one is only discovered by software that did not build it. SiVa already
accepts ours; DigiDoc4 is the second opinion. Produce one with:

```bash
ALLKIRI_INTEGRATION=1 ALLKIRI_ARTEFACTS=/some/directory \
  vendor/bin/phpunit tests/Integration/MobileIdDemoTest.php \
  --filter testAnArchivedContainerIsRecognisedAsLtaBySiva
```

## The card items, through the demo application

Items 12 to 15 need a browser, so run `examples/demo-app` rather than writing a
script. It signs in with a card, signs an upload with one, and validates the
result, which is all four items in one sitting.

The Web eID extension refuses to work on an insecure origin, so the demo needs
HTTPS and an origin the server agrees with exactly. `php -S` does not speak TLS,
so serve it behind something that does; with Caddy, in two terminals:

```bash
php -S 127.0.0.1:8080 -t examples/demo-app/public examples/demo-app/public/index.php
caddy reverse-proxy --from localhost:8443 --to 127.0.0.1:8080
```

and open <https://localhost:8443>, the origin the demo expects by default.
`examples/demo-app/README.md` says what Caddy needs the first time. An origin
mismatch is the failure to expect first, and it is indistinguishable from a
rejected token unless you look: the card signs the origin, so the server refuses
a token signed for anything else.

Item 15 is about the extension rather than about this library, but a browser
that cannot reach the card at all is worth knowing before someone reports it as
a signing bug.

## Signing in DigiDoc4 test mode

Test Mobile-ID numbers are published at
<https://github.com/SK-EID/MID/wiki/Test-number-for-automated-testing-in-DEMO>;
`+37200000766` with personal code `60001019906` is the usual one. Smart-ID demo
accounts are at <https://sk-eid.github.io/smart-id-documentation/test_accounts.html>.

## When something fails

Record what DigiDoc4 said, keep the container, and open an issue with both.
A container that DigiDoc4 rejects and allkiri accepts is the most valuable
bug report this project can get.
