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
<!-- only for the ID card: your own copy, see below -->
<script src="/web-eid.js" integrity="sha384-eNqE5qChFP5o6ucg8NHzHOkGCd1MavcHSKU2gSR/Dp8eDOf3d9GBlayz3btZ15hB"></script>
```

`allkiri-qr.js` must come first, because `allkiri.js` picks it up when it loads.
Leave it out if you never show a Smart-ID QR code.

**Serve web-eid.js yourself.** No CDN has it: the package is published only to
Web eID's own npm registry, not to npm's public one, so a jsDelivr or unpkg
address for it answers 404. Take `iife/web-eid.js` from the zip attached to a
[web-eid.js release](https://github.com/web-eid/web-eid.js/releases), serve it
from your own origin, and pin it with an `integrity` hash. The hash above is
that file's at 2.1.0; `examples/demo-app` keeps the same copy.

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
// A SessionDataException here means the store handed back something that
// cannot be read as a session; start again.
$session = SmartIdSession::fromJson($_SESSION['sid']);
$link = $session->deviceLink($configuration->scheme, $configuration->relyingPartyNameBase64());

echo json_encode(['link' => $link->url($session->sessionSecret, $session->elapsedSeconds())]);
```

See [smart-id.md](smart-id.md) for the whole flow and for what must stay on the
server.

`stop()` ends both the redrawing and the polling, and cancels the link request
in flight; an aborted `signal`, if you pass one, does the same. The promise
settles when the session does, either way, and rejects as cancelled once
stopped.

Only one link request is in flight at a time, so a slow link endpoint is not
asked again before it has answered. One still unanswered after three intervals
is cancelled and replaced, since the link it would bring back is stale.

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

An answer that cannot be read is an error too, immediately, quoting the start of
what came back. This matters most while polling: a PHP notice ahead of your JSON,
a proxy's error page, or an HTML login redirect in front of your endpoints would
otherwise be taken for "not finished yet", and the loop would go on asking long
after the session it was waiting for had been finished and consumed. The person
then sees a failure with the wrong cause, minutes after the thing they did
actually succeeded.

A poll is asked again in one case only: when no answer from your server arrived,
because the network failed or a gateway in front of it answered 502, 503 or 504.
It waits the poll interval, then twice, four and eight times it, never past the
timeout. If the timeout comes first, it rejects with the last of those errors,
and that error's `retries` says how many times it asked again. Anything your
server did say, a 500 included, ends the wait at once.

So your poll endpoint can be asked again about a session it has already finished
and forgotten, when its answer was lost on the way back. Keep the finished answer
for a little while and give it again to a poll that finds nothing in progress;
`examples/demo-app` keeps it for a minute.

What to show a person is your decision, and it should not be the message: these
are for your logs. `docs/mobile-id.md` and `docs/smart-id.md` list the outcomes
worth distinguishing.

For the ID card, `allkiri.describeWebEidError(error)` does that part. Given the
error `cardLogin()` or `cardSign()` rejected with, it returns `{code, who, text}`:
`who` is `person`, `operator` or `developer`, and `text` is a sentence in English
for them. Anything that is not a known web-eid.js error gives `null`. The codes
and what they mean are in [web-eid.md](web-eid.md#when-the-card-fails).

## Browser support

ES5 syntax, `fetch` and `Promise`. That is every browser the Web eID extension
supports and then some. No polyfills are bundled; add your own if you support
something older.
