# The allkiri demo

A small application that signs in with all four Estonian eID means, signs an
uploaded file with any of them, archives the result, and validates a container.
Plain PHP, no framework, one file of server code.

It exists to be read. Every endpoint is a few lines, and the parts that matter —
storing a challenge against the browser session, showing a verification code
before the person touches their phone, keeping the Smart-ID session secret on
the server — are commented where they happen.

**Not for production.** No accounts, no authorisation, no rate limiting, and
uploads live in a temporary directory keyed by session. It also reports errors
verbatim, which a real application must not do.

## Running it

```bash
composer install
php -S localhost:8080 -t examples/demo-app/public
```

Then open <http://localhost:8080>.

Mobile-ID, Smart-ID and validation work over plain HTTP. **The ID card does
not**: the Web eID extension refuses to work on an insecure origin. For that you
need HTTPS and an origin the server agrees with:

```bash
ALLKIRI_DEMO_ORIGIN=https://localhost:8443 php -S localhost:8443 -t examples/demo-app/public
```

with a TLS terminator in front, or run it behind whatever you normally use.
`ALLKIRI_DEMO_ORIGIN` must be exactly what the browser reports as
`location.origin`, because the card signs it.

If every HTTPS call fails with curl error 60, your PHP has no `curl.cainfo`
configured, which is common on Windows. Point it at a bundle:

```bash
ALLKIRI_CA_BUNDLE=/path/to/cacert.pem php -S localhost:8080 -t examples/demo-app/public
```

## Test credentials

All published by SK for their demo services. No real person is involved.

| Means | What to use |
|---|---|
| Mobile-ID | `+37200000766` with identity code `60001019906` |
| Smart-ID (sign in) | identity code `50001029996` |
| Smart-ID (signing) | document number `PNOEE-50001029996-DEMO-Q` |
| ID card | a physical test card and reader |

More numbers, including ones that fail in documented ways, are in
[the Mobile-ID list](https://github.com/SK-EID/MID/wiki/Test-number-for-automated-testing-in-DEMO)
and [the Smart-ID list](https://sk-eid.github.io/smart-id-documentation/test_accounts.html).

## What it shows

**Signing in.** Three different shapes. The card is synchronous from the page's
point of view: ask the server for a challenge, have the card sign it, post the
token back. Mobile-ID and Smart-ID push a request to a phone, so the page shows
a verification code and polls the server until it says the session finished.

**Signing.** An upload becomes an ASiC-E container, and each signature is added
to the same container, so you can sign one file with several means and watch
them accumulate. Signing with the card is four steps alternating between browser
and server, because the card's certificate has to be known before the digest
exists.

**Archiving.** One button, which lays an archive timestamp over everything
signed so far. That is what keeps a signature verifiable after the algorithms
behind it weaken, and it can be pressed again later.

**Validating.** Upload any container, signed here or elsewhere, and read the
report.

## Where to look

| File | What it is |
|---|---|
| `app.php` | every endpoint, and the only place the library is called |
| `public/index.php` | routing, and nothing else |
| `views/page.php` | the page, using `assets/allkiri.js` from the library |

The page loads `web-eid.js` from a CDN, `allkiri-qr.js` and `allkiri.js` from
the library itself, so what you see working here is the same code an application
would ship.
