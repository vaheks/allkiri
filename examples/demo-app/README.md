# The allkiri demo

A small application that signs in with an ID card, Mobile-ID or Smart-ID, signs
an uploaded file with any of them, archives the result, and validates a
container.
Plain PHP, no framework: one file of endpoints and one of configuration.

It exists to be read. Every endpoint is a few lines, and the parts that matter —
storing a challenge against the browser session, showing a verification code
before the person touches their phone, keeping the Smart-ID session secret on
the server — are commented where they happen.

**Not for production.** It refuses cross-site requests with a CSRF token of its
own, where a real application would use its framework's protection, and it has
no accounts, no authorisation and no rate limiting. Uploads are kept in
`examples/demo-app/var/`, one container per browser session under a random
name, and nothing deletes them. It also reports errors verbatim, which a real
application must not do.

It has two modes. In `demo` it talks to SK's free test services with the
credentials SK publishes, and nothing it produces is a valid signature. In
`live` it talks to the real services with your own credentials, and everything
it produces is real. The page says which, in a banner, because the two look
otherwise identical.

## Running it

```bash
composer install
php -S localhost:8080 -t examples/demo-app/public examples/demo-app/public/index.php
```

Then open <http://localhost:8080>.

The last argument makes `index.php` the server's router. The library's two
scripts, `/allkiri.js` and `/allkiri-qr.js`, are routes in it rather than files,
and without the router PHP before 8.4 answers 404 for a path that looks like a
file it cannot find.

Mobile-ID, Smart-ID and validation work over plain HTTP. **The ID card does
not**: the Web eID extension refuses to work on an insecure origin, so the page
needs HTTPS, on the origin the server expects. `php -S` does not speak TLS, so
put something that does in front of it. With [Caddy](https://caddyserver.com),
in two terminals:

```bash
php -S 127.0.0.1:8080 -t examples/demo-app/public examples/demo-app/public/index.php
caddy reverse-proxy --from localhost:8443 --to 127.0.0.1:8080
```

Then open <https://localhost:8443>. That is the origin the demo expects by
default, so nothing needs configuring. Caddy issues the certificate for
`localhost` from a certificate authority of its own, and tries to add that
authority to the system's trust store the first time, which may ask for an
administrator's password. The browser accepts the page only once it is there.

Anything else that terminates TLS works the same way. What matters is that
`ALLKIRI_ORIGIN` is exactly what the browser reports as `location.origin`,
because the card signs it: set it whenever the page is served from anywhere but
`https://localhost:8443`.

If every HTTPS call fails with curl error 60, your PHP has no `curl.cainfo`
configured, which is common on Windows. Point it at a bundle:

```bash
ALLKIRI_CA_BUNDLE=/path/to/cacert.pem php -S localhost:8080 -t examples/demo-app/public examples/demo-app/public/index.php
```

## Live mode

Only when you have contracts with SK, and only from a machine whose public
address they have registered. Copy `.env.example` at the repository root to
`.env` and fill in five values:

```
ALLKIRI_MODE=live
ALLKIRI_MID_RP_UUID=...
ALLKIRI_MID_RP_NAME=...
ALLKIRI_SMARTID_RP_UUID=...
ALLKIRI_SMARTID_RP_NAME=...
ALLKIRI_ORIGIN=https://your.host
```

Live mode refuses to start if any of them is missing, and names all of them at
once. It also refuses the identifiers SK publishes for the demo environment, and
demo mode refuses your real ones, because the failure worth preventing is a
signature made against the wrong services that looks exactly like one made
against the right ones.

Live mode marks the session cookie `Secure`, so serve it over HTTPS. Over plain
HTTP the browser never sends that cookie back, and every call after the page is
refused.

Nothing else changes. The timestamp service, the revocation responders and the
trust anchors all come from `Environment::production()`, which needs no
configuration.

The repeatable version of the same thing is `composer test:live`, which signs
once with each remote mean and validates the result in SiVa production. See
[docs/releasing.md](../../docs/releasing.md).

## Logging

```bash
ALLKIRI_LOG=/tmp/allkiri.log ALLKIRI_LOG_HTTP=1 php -S localhost:8080 -t examples/demo-app/public examples/demo-app/public/index.php
```

One JSON object per line, holding three things at once: the audit trail the
application writes at each stage, the library's own milestones, and, with
`ALLKIRI_LOG_HTTP=1`, every remote call it makes. Add
`ALLKIRI_LOG_PERSONAL_DATA=1` to put bodies and whole URLs in the transcript,
which is a debugging setting rather than a verbosity one. Credentials are never
logged whatever you set.

The point of it here is the shape rather than the implementation. See
[docs/logging.md](../../docs/logging.md).

## Test credentials

All published by SK for their demo services. No real person is involved.

| Means | What to use |
|---|---|
| Mobile-ID | `+37200000766` with identity code `60001019906` |
| Smart-ID | identity code `50001029996` |
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
exists. Smart-ID has the same need in another form: it gives out a certificate
only for one account, not a person. After a Smart-ID sign-in the demo keeps that
account. Otherwise it first asks the phone which account will sign, which is one
more prompt before the PIN.

**Archiving.** One button, which lays an archive timestamp over everything
signed so far. That is what keeps a signature verifiable after the algorithms
behind it weaken, and it can be pressed again later.

**Validating.** Upload any container, signed here or elsewhere, and read the
report.

## Where to look

| File | What it is |
|---|---|
| `config.php` | the two modes, and the only place the environment is read |
| `logger.php` | a PSR-3 logger in thirty lines, writing JSON lines |
| `app.php` | every endpoint, and the only place the library is called |
| `public/index.php` | routing, and the method and token checks every call passes first |
| `views/page.php` | the page, using `assets/allkiri.js` from the library |
| `public/vendor/web-eid.js` | a pinned copy of web-eid.js, for the ID card |

The page loads `allkiri-qr.js` and `allkiri.js` from the library itself, so what
you see working here is the same code an application would ship.

## web-eid.js

The ID card needs web-eid.js, and no CDN serves it: the package is published
only to Web eID's own npm registry, not to npm's public one. So the demo keeps a
copy of `iife/web-eid.js` from the
[web-eid.js 2.1.0 release](https://github.com/web-eid/web-eid.js/releases/tag/v2.1.0)
(`web-eid.js-v2.1.0.zip`), with the MIT licence it carries, and the page loads
it with an `integrity` hash, so a changed file is refused.

| | |
|---|---|
| Version | 2.1.0 |
| SHA-256 | `ad1ae8554b301bf28a1609077ba971e4b3e6db49059fdee6c745a785dd3f7735` |
| `integrity` | `sha384-eNqE5qChFP5o6ucg8NHzHOkGCd1MavcHSKU2gSR/Dp8eDOf3d9GBlayz3btZ15hB` |

To update it, take `iife/web-eid.js` from a newer release's zip, replace the
file, and put its hash in `views/page.php` and in this table:

```bash
php -r 'echo "sha384-", base64_encode(hash_file("sha384", "examples/demo-app/public/vendor/web-eid.js", true)), PHP_EOL;'
```
