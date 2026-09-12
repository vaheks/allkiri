# The browser half

Two files in `assets/`, no dependencies and no build step:

| File | What it is |
|---|---|
| `allkiri.js` | drives the Web eID extension, shows verification codes, polls your server |
| `allkiri-qr.js` | a QR encoder, because Smart-ID device links need one every second |

Copy them into your public directory, or serve them straight from
`vendor/vaheks/allkiri/assets/`. They are plain scripts that define
`window.allkiri` and `window.allkiriQr`, and they also work as CommonJS modules.

```html
<script src="/allkiri-qr.js"></script>
<script src="/allkiri.js"></script>
<!-- only for the ID card -->
<script src="https://cdn.jsdelivr.net/npm/@web-eid/web-eid-library@2/dist/iife/web-eid.js"></script>
```

`allkiri-qr.js` must come first, because `allkiri.js` picks it up when it loads.
Leave it out if you never show a Smart-ID QR code.

## What it decides: nothing

Every answer goes to your server, which is where the token is checked and the
signature is built. A page cannot validate a signature and must not pretend to.
These helpers move bytes between the extension, your endpoints and the screen.

So the shape of your application does not change. You write the endpoints; this
calls them.

## Configuration

```js
allkiri.configure({
  csrfToken: document.querySelector('meta[name="csrf-token"]').content,
  csrfHeader: 'X-CSRF-Token',   // 'X-CSRF-TOKEN' for Laravel
  credentials: 'same-origin',
  headers: { 'Accept-Language': 'et' }
});
```

Anything set here applies to every request the helpers make. Individual calls
take the same keys and win over it.

## Signing in

### The ID card

```js
allkiri.cardLogin({
  challengeUrl: '/api/card/challenge',
  loginUrl: '/api/card/login',
  lang: 'et'
}).then(showTheUser).catch(explain);
```

Your challenge endpoint returns `{nonce}` and remembers the challenge against
the browser session. Your login endpoint receives `{token}` and gives it to
`WebEidAuthenticator::validate()`. See [web-eid.md](web-eid.md).

The extension is checked before the challenge is asked for, so a browser without
it does not leave a session open on your server that nothing will ever answer.

### Mobile-ID and Smart-ID

Both are the same shape from the page's point of view: start, show a
verification code, wait.

```js
allkiri.notificationFlow({
  startUrl: '/api/mobile-id/login/start',
  pollUrl: '/api/mobile-id/login/poll',
  body: { phoneNumber: '+37200000766', identityCode: '60001019906' },
  onCode: function (code) {
    allkiri.showVerificationCode(document.getElementById('code'), code);
  },
  timeout: 120000
}).then(showTheUser).catch(explain);
```

Your start endpoint returns `{verificationCode}`; your poll endpoint returns
`{done: false}` until the person answers and `{done: true, …}` once they have.
Show the code before they touch their phone: it is the only thing that tells
them the request on their screen is the one they started on yours.

`signal` takes an `AbortSignal`, so a cancel button is two lines.

## Signing

Mobile-ID and Smart-ID sign with the same `notificationFlow`, pointed at your
signing endpoints. The ID card needs four steps, because the card's certificate
has to be known before the digest exists:

```js
allkiri.cardSign({
  prepareUrl: '/api/card/sign/prepare',
  completeUrl: '/api/card/sign/complete'
}).then(done).catch(explain);
```

The page fetches the signing certificate, posts it with the algorithms the card
supports, receives `{hash, hashFunction}` from `WebEidSigningSession::forBrowser()`,
asks for PIN 2, and posts the value back. Your two endpoints are the two halves
of `prepare()` and `finalize()`.

## The Smart-ID QR code

A device-link QR carries how many seconds have passed since the session started,
and the app refuses a stale one. A new link, with a new authentication code, is
needed about once a second.

Only your server can mint those: the session secret that signs them must never
reach a browser. So the helper asks your server for each new link rather than
building any itself.

```js
var running = allkiri.deviceLinkQr({
  linkUrl: '/api/smart-id/link',     // returns {link: "https://smart-id.com/dynamic-link/…"}
  pollUrl: '/api/smart-id/sign/poll',
  element: document.getElementById('qr'),
  size: 240,
  level: 'M'
});

cancelButton.onclick = running.stop;
running.promise.then(done).catch(explain);
```

Your link endpoint rebuilds the link each time it is asked:

```php
$session = SmartIdSession::fromJson($_SESSION['sid']);
$link = $session->deviceLink($configuration->scheme, $configuration->relyingPartyNameBase64());

echo json_encode(['link' => $link->url($session->sessionSecret, $session->elapsedSeconds())]);
```

See [smart-id.md](smart-id.md) for the whole flow and for what must stay on the
server.

`stop()` ends both the redrawing and the polling. The promise settles when the
session does, either way.

## The QR encoder on its own

```js
var svg = allkiriQr.svg('https://example.org', { level: 'M', size: 240 });
element.innerHTML = svg;

var matrix = allkiriQr.encode('https://example.org', { level: 'M' });
// matrix.size, matrix.modules[row][column] — true is dark
```

Byte mode, error-correction levels L and M, versions 1 to 20, which is more than
a Smart-ID link needs. It picks the smallest version that fits and the mask with
the lowest penalty, as the standard requires.

It is tested two ways: six known encodings are pinned by the digest of their
module matrix, and 1208 strings are encoded and then read back with an
independent decoder (`jsqr`) at every length, both levels, and all eight masks.
That second test is how a reversed generator polynomial was found, which
produced codes that looked entirely plausible and scanned as nothing.

```bash
node tests/js/qr-golden.mjs                                  # no dependencies
NODE_PATH=/path/to/node_modules node tests/js/qr-roundtrip.mjs  # needs jsqr
```

## Errors

Everything rejects with an `Error`. When your endpoint answers with a JSON body
carrying `message` or `error`, that text becomes the message, so your own
wording reaches the page. A missing Web eID extension rejects with a message
naming web-eid.js.

What to show a person is your decision, and it should not be the message: these
are for your logs. `docs/mobile-id.md` and `docs/smart-id.md` list the outcomes
worth distinguishing.

## Browser support

ES5 syntax, `fetch` and `Promise`. That is every browser the Web eID extension
supports and then some. No polyfills are bundled; add your own if you support
something older.
