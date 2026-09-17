# Going live

allkiri is a library. The services it talks to in production are run by SK ID
Solutions (SK), the Information System Authority (RIA), Zetes and the European
Commission. Some of them need a contract and a registered server, some are
free. This page says which you need for what, what each costs, and what to
check before the first real person signs.

The facts here were checked against the providers' own pages on 17 September
2026. Prices and terms change, so follow the links before you order anything.

## What each use case needs

| You want to | Contracts | Free, used without asking |
|---|---|---|
| Sign people in with an ID card | none | the card's OCSP responder, the trusted lists |
| Sign people in with Mobile-ID | SK: Mobile-ID | the trusted lists |
| Sign people in with Smart-ID | SK: Smart-ID | the certificate's OCSP responder, the trusted lists |
| Sign documents with an ID card | SK: timestamping | the card's OCSP responder, the trusted lists |
| Sign documents with Mobile-ID or Smart-ID | SK: that service, and timestamping | OCSP, the trusted lists |
| Seal documents as an organisation | SK: an e-seal certificate, and timestamping | OCSP, the trusted lists |
| Validate containers you receive | none | the trusted lists |
| Ask RIA's SiVa for a second opinion | none | SiVa |

Every contract with SK comes with one more requirement: SK recognises your
server by its public IP address. Register the address of every server that
calls, or it is refused.

The ID card needs no contract and no registration, but the person needs the ID
software installed and your site needs HTTPS.

### Three examples

**A members' area where people sign in.** Mobile-ID and Smart-ID contracts,
nothing else. Add the ID card for free. No timestamps, because nothing is
signed.

```php
$allkiri = new Allkiri(Environment::production(), cache: $cache, logger: $logger);

$mobileId = $allkiri->mobileIdAuthenticator(MobileIdConfiguration::production($_ENV['MID_UUID'], $_ENV['MID_NAME']));
$smartId = $allkiri->smartIdAuthenticator(SmartIdConfiguration::production($_ENV['SID_UUID'], $_ENV['SID_NAME']));
$idCard = $allkiri->webEidAuthenticator(WebEidConfiguration::forOrigin('https://example.ee'));
```

**A site where contracts are signed.** Everything above, plus SK's timestamping
service. Every signature takes one timestamp. A Smart-ID signature by identity
code takes two Smart-ID requests: one to learn which device signs, one for the
signature ([smart-id.md](smart-id.md#signing)).

```php
$mobileIdSigner = $allkiri->mobileIdSigner(MobileIdConfiguration::production($_ENV['MID_UUID'], $_ENV['MID_NAME']));
$smartIdSigner = $allkiri->smartIdSigner(SmartIdConfiguration::production($_ENV['SID_UUID'], $_ENV['SID_NAME']));
$idCardSigner = $allkiri->webEidSigner();
```

**An archive that checks what it receives.** No contract at all:

```php
$report = (new Allkiri(Environment::production(), cache: $cache))->validator()->validateFile('leping.asice');
```

Add SK's timestamping service only if you also add archive timestamps
(`SigningService::archive()`), which keep old signatures provable.

### What it might cost

An estimate, not a quote: a site where 1,000 people a month sign in with
Smart-ID and 200 of them sign a document with it.

| | Requests | Plan | Per month, VAT excluded |
|---|---|---|---|
| Smart-ID | 1,000 sign-ins + 200 × 2 for signing = 1,400 | I | about €153 (1,400 × €0.109) |
| Timestamps | 200 | I | €36 (covers 1,000) |

This assumes requests beyond a plan's minimum are billed at that plan's price,
and that the request that learns which device signs is billed like any other.
SK's price list does not say either outright. Ask SK before you rely on it.

## The services

### Smart-ID

| | |
|---|---|
| Provider | SK ID Solutions, [skidsolutions.eu/services/smart-id](https://www.skidsolutions.eu/services/smart-id/) |
| You get | a relying-party UUID, which is a shared secret, and a relying-party name, which the person sees in bold on their phone |
| Access | the UUID and name, from the addresses you registered; SK also asks you to pin its TLS key ([smart-id.md](smart-id.md#pinning-sks-tls-key)) |
| Price | per authentication or signing request; from 1 June 2026, plan I is €60 a month for up to 550 requests (€0.109 each), down to €0.0106 at 3 million ([price list](https://www.skidsolutions.eu/price-list/)) |
| Production | `https://rp-api.smart-id.com/v3`, set by `SmartIdConfiguration::production()` |
| Demo | `https://sid.demo.sk.ee/smart-id-rp/v3`, free, with SK's published demo credentials: `SmartIdConfiguration::demo()` |

SK also sells Smart-ID through partners. A partner gives you its own API, which
this library does not speak.

Choose a relying-party name people recognise. It is the only thing on the phone
that says who is asking.

### Mobile-ID

| | |
|---|---|
| Provider | SK ID Solutions, [skidsolutions.eu/services/mobile-id](https://www.skidsolutions.eu/services/mobile-id/). People get Mobile-ID itself from their mobile operator |
| You get | a relying-party UUID and name, agreed when you register |
| Access | the UUID, the name and your registered address together; SK's [documentation](https://github.com/SK-EID/MID) says a relying party must also pin its TLS certificate ([mobile-id.md](mobile-id.md#pinning-sks-tls-key)) |
| Price | per authentication or signing request; from 1 June 2026, plan I is €33 a month for up to 300 requests (€0.109 each), down to €0.0144 at a million |
| Production | `https://mid.sk.ee/mid-api`, set by `MobileIdConfiguration::production()` |
| Demo | `https://tsp.demo.sk.ee/mid-api`, free, answering only for [SK's test numbers](https://github.com/SK-EID/MID/wiki/Test-number-for-automated-testing-in-DEMO) |

### Timestamps

A signature at level T, LT or LTA carries a timestamp. That is what DigiDoc4
and SiVa expect, and it is allkiri's default.

| | |
|---|---|
| Provider | SK ID Solutions, [timestamping service](https://github.com/SK-EID/Timestamping/wiki/Service-Technical-Information) |
| Access | a monthly subscription, granted to your server's address. Any other address gets HTTP 403 |
| Price | from 1 July 2022: €36 a month for 1,000 stamps (€0.036 each), down to €3,000 for 500,000 (€0.006 each) |
| Production | `http://tsa.sk.ee`, set by `Environment::production()`. The tokens are signed, and allkiri refuses one whose authority is not on a trusted list, so plain HTTP is not a weakness here |
| Demo | `http://tsa.demo.sk.ee/tsa`, free, no contract |

Another qualified timestamp authority works if its country's trusted list is
loaded (`Environment::euListOfLists(['EE', 'XX'])`), because allkiri accepts a
timestamp only from an authority a loaded list names. This library has not
been tested with any authority but SK's.

### Revocation (OCSP)

Every certificate names the responder that answers for it, and allkiri asks
that one. For Estonian certificates they are free:

- SK's responders at `aia.sk.ee`, for ID cards issued by SK, Mobile-ID and
  Smart-ID. SK's certification practice statements call them "free of charge
  and publicly accessible".
- Zetes' responder at `ocsp.eidpki.ee`, for Thales ID cards issued since
  November 2025. Zetes' terms make it free as well.

SK also sells a revocation service at `ocsp.sk.ee` with a service level
agreement: from €9.60 a month for 400 queries. It answers only for
certificates SK issued, so a Thales card still needs Zetes' responder. If you
buy it, send SK's certificates to it with `Environment::withOcspUrlOverrides()`
([signing.md](signing.md#services-and-what-they-cost)).

### The ID card (Web eID)

No contract, no registration, no fee. The person installs the ID software from
[id.ee](https://www.id.ee/), which includes the Web eID browser extension, and
the extension has to be switched on. Your site must be served over HTTPS, and
its origin configured exactly as the browser reports it
([web-eid.md](web-eid.md)).

### Trusted lists

The European list of trusted lists (`ec.europa.eu`) and the Estonian list
(`sr.riik.ee`) are free and need no registration. allkiri downloads them the
first time it needs trust. Give it a PSR-16 cache, or it downloads them again
for every new `Allkiri` ([trust.md](trust.md#caching)).

### SiVa

RIA publishes its production validation service at
`https://siva.eesti.ee/V3/validate` with a service level agreement and no
access conditions. It has been behind Cloudflare since June 2026, which now
and then answers a server with a challenge instead of a verdict
([validation.md](validation.md)).

SiVa receives the whole container, documents included. Decide whether that is
acceptable for what you validate.

### E-seals

An organisation signs with an e-seal certificate. SK's cost €205 to €610,
depending on the term and on whether the key is on a qualified device. SK's
practice statement for organisation certificates has the key on a qualified
device or a certified hardware module, not in a file. For such a key,
implement `Allkiri\Signing\Signer` for the device; `LocalKeySigner::fromPkcs12()`
is for a key you hold as a file ([signing.md](signing.md)).

## Your server

- **A fixed public address, registered with SK** for Mobile-ID, Smart-ID and
  timestamping. Every server that calls them needs it, including the one you
  test from. SK answers any other address with 401 (Mobile-ID and Smart-ID) or
  403 (timestamping).
- **HTTPS** for your site. The ID card needs it, and so does the page the
  Smart-ID app returns to on a phone.
- **Outbound access** to `mid.sk.ee`, `rp-api.smart-id.com`, `tsa.sk.ee`,
  `aia.sk.ee`, `ocsp.eidpki.ee`, `ec.europa.eu` and `sr.riik.ee`, plus
  `siva.eesti.ee` if you use SiVa, and the lists of any other country you
  load.
- **TLS that SK accepts.** From 2 November 2026, Mobile-ID and Smart-ID accept
  only TLS 1.3 with `TLS_AES_256_GCM_SHA384`, or TLS 1.2 with
  `ECDHE-RSA-AES256-GCM-SHA384` or `DHE-RSA-AES256-GCM-SHA384`
  ([SK's notice](https://www.skidsolutions.eu/news/mobile-id-and-smart-id-endpoint-change-on-2-november-2026/)).
  Check from your server:

  ```bash
  openssl s_client -connect rp-api.smart-id.com:443 -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 </dev/null
  ```

- **PHP 8.2 or newer** with `curl`, `dom`, `mbstring`, `openssl` and `zlib`,
  and a CA bundle curl can find.

## Before the first real person

- The relying-party UUIDs and names are in your secret store, not in your code
  or its history.
- Your server's address is registered, and a sign-in with each means works
  from it. The demo application in live mode is a quick way to try
  ([examples/demo-app](../examples/demo-app/README.md)).
- The relying-party names are ones people recognise.
- Trusted lists are cached.
- Personal data stays out of your logs ([logging.md](logging.md)).
- If you pin SK's TLS keys, the pins are in configuration and someone reads
  [SK's news](https://www.skidsolutions.eu/news/). SK replaces the Smart-ID
  production certificate, with a new key, on 6 October 2026.
- A container signed in production opens in DigiDoc4 without warnings.

[releasing.md](releasing.md) describes the smoke test this repository runs
against production before a release.
