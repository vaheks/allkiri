# Web eID (the ID card)

Web eID is how a browser reaches an Estonian ID card. The older plugins are
being retired: e-services must move to it by the end of 2026.

Three things are involved and only one of them is this library. The person
needs the Web eID browser extension and its native application installed, the
page uses `web-eid.js` to talk to them, and the server does what is described
here. Nothing polls: the waiting happens in the browser.

Both Estonian card families work the same way. IDEMIA cards carry elliptic-curve
P-384 keys, and the Thales cards issued since November 2025 carry their own; the
card says what it can do and the library uses it.

## Configuring

```php
use Allkiri\Allkiri;
use Allkiri\Config\Environment;
use Allkiri\WebEid\WebEidConfiguration;

$allkiri = new Allkiri(Environment::production());
$configuration = WebEidConfiguration::forOrigin('https://example.ee');
```

There is no relying-party contract and no service to register with. The one
thing that must be right is the origin.

### The origin is load-bearing

The card signs `hash(origin) || hash(challenge)` and the token carries neither,
so the server supplies both from its own knowledge. If the configured origin is
not exactly what the browser used, nothing verifies. If it were somehow an
attacker's origin, their token would verify at your site, which is the relay
attack the format exists to prevent.

The form is the ASCII serialisation: `https://host[:port]`, no trailing slash,
no path. The safest way to get it is to copy `location.origin` from the browser.
`WebEidOrigin` normalises what it is given: the default port 443 is dropped
because a browser omits it, and an internationalised host becomes Punycode, so
`https://päike.ee` is signed as `https://xn--pike-loa.ee`.

Only HTTPS. The extension refuses to work anywhere else.

## Signing in

```php
// GET /auth/challenge
$challenge = $allkiri->webEidAuthenticator($configuration)->challenge();
$_SESSION['web-eid'] = json_encode($challenge);

header('Content-Type: application/json');
echo json_encode(['nonce' => $challenge->nonce]);
```

The page then calls `webeid.authenticate({challengeNonce})` and posts the token
back:

```php
// POST /auth/login
// A SessionDataException here means the store handed back something that
// cannot be read as a challenge; ask for a new one.
$challenge = WebEidChallenge::fromJson($_SESSION['web-eid']);
unset($_SESSION['web-eid']);            // one challenge, one use

$identity = $allkiri->webEidAuthenticator($configuration)->validate($token, $challenge);

$identity->semanticsIdentifier();       // "PNOEE-38001085718" — the account key
$identity->fullName();
```

**Store the challenge against the browser session that asked for it, and use it
once.** The token carries no nonce, so looking one up by session is the only
way, and that is exactly what stops an attacker forcing a victim's browser to
log in with the attacker's card.

### What is checked

The token, its signature, and the certificate's key usage and policies are
checked by `web-eid/web-eid-authtoken-validation-php`, the implementation RIA
maintains. Trust and revocation are done by allkiri with the same trust store,
chain builder and OCSP client the rest of the library uses, so a card is judged
exactly as a Mobile-ID or Smart-ID certificate is.

A token is refused unless:

- the challenge has not expired (five minutes by default; nothing in the token
  says when it was made, so the website's own record of when it issued the
  challenge is what counts);
- the signature verifies over this origin and this challenge;
- the certificate can be used for client authentication;
- its policy is not one you disallowed;
- it is valid now, chains to a trust anchor, and is not revoked;
- it names a person by personal code, passport or identity card number, so an
  e-seal or an organisation certificate cannot sign anyone in. The identifier
  keeps its type and country in `semanticsIdentifier()`: a passport is
  `PASEE-…`, never the same account as a personal code `PNOEE-…`.

Mobile-ID certificates are refused by their certificate policies, so a Mobile-ID
certificate cannot be presented through Web eID. A site that asked for a card
should be answered by a card. Two policies are refused, listed in
`WebEidConfiguration::MOBILE_ID_POLICIES`:
- `1.3.6.1.4.1.10015.1.3`, the Estonian Mobile-ID policy;
- `1.3.6.1.4.1.10015.18.1`, the one SK has issued under since 2022.

Policies are compared exactly, not by prefix.
`withDisallowedCertificatePolicies()` replaces allkiri's list. The Web eID library
refuses the Estonian Mobile-ID policies on its own as well, so an empty list does
not admit them.

## Signing a container

Four steps, alternating between the browser and the server.

```php
// 1. the page calls webeid.getSigningCertificate() and posts the result
// 2. the server prepares
$signer = $allkiri->webEidSigner();
$container = AsicContainer::create(DataFile::fromPath('leping.pdf'));

$session = $signer->prepare($container, $certificate, $supportedSignatureAlgorithms);
$_SESSION['signing'] = json_encode($session);

echo json_encode($session->forBrowser());   // {"hash": "...", "hashFunction": "SHA-384"}
```

```php
// 3. the page calls webeid.sign(certificate, hash, hashFunction), asking for PIN 2
// 4. the server finishes
$session = WebEidSigningSession::fromJson($_SESSION['signing']);

$result = $signer->complete($container, $session, $signature, CardAlgorithm::fromArray($signatureAlgorithm));
file_put_contents('leping.asice', $allkiri->writer()->write($result->container));
```

The container passed to `complete()` must be the same one passed to
`prepare()`, down to the bytes of its data files;
[signing.md](signing.md#between-the-two-requests) says where to keep it in
between. Card signing has no session
timeout of its own: the only limit is the one on every prepared signature, ten
minutes by default (see [signing.md](signing.md#how-long-a-prepared-signature-lasts)).
A person who takes longer has to start again.

### Why the algorithm is negotiated in advance

`sign()` is told only the hash function. The card chooses the padding itself and
reports it afterwards, but the XAdES has to declare its signature method at step
2, before the signature exists. So the library reads the card's
`supportedSignatureAlgorithms`, picks one that matches the key in the
certificate, and refuses at step 4 if what came back is not that one. Otherwise
the container would declare a method it does not use, and no validator would
accept it.

Left alone it takes the strongest hash the card offers, preferring PSS over
PKCS#1 v1.5 where an RSA card offers both. `SigningOptions::withAlgorithm()`
overrides that, and is refused up front if the card does not offer it.

SHA-224 and the SHA-3 family are reported by some cards and have no signature
method in the profile allkiri produces, so they are passed over.

## When the card fails

`allkiri.cardLogin()` and `cardSign()` reject with web-eid.js's own error. Its
`code` is one of thirteen, and its message is written for developers.
`allkiri.describeWebEidError(error)` says who can act on it and gives a sentence
in English for them, or `null` for anything that is not a Web eID error:

| Code | Who can act | What it means |
|---|---|---|
| `ERR_WEBEID_EXTENSION_UNAVAILABLE` | the person | the browser extension is missing or turned off |
| `ERR_WEBEID_NATIVE_UNAVAILABLE` | the person | the Web eID application is not installed |
| `ERR_WEBEID_VERSION_MISMATCH` | the person | the extension, the application or both need updating; `requiresUpdate` says which |
| `ERR_WEBEID_USER_CANCELLED` | the person | they closed the dialog |
| `ERR_WEBEID_USER_TIMEOUT` | the person | they did not answer in time |
| `ERR_WEBEID_NATIVE_FATAL` | the person | the application failed, often because of the reader; trying again may help |
| `ERR_WEBEID_CONTEXT_INSECURE` | the operator | the page is not served over HTTPS |
| `ERR_WEBEID_NATIVE_INVALID_ARGUMENT` | the developer | the application was given a bad argument, such as a short challenge |
| `ERR_WEBEID_ACTION_PENDING` | the developer | the same action was started again before the first finished; disable the button meanwhile |
| `ERR_WEBEID_MISSING_PARAMETER` | the developer | web-eid.js was called without something it needs |
| `ERR_WEBEID_ACTION_TIMEOUT` | the developer | the extension never answered; a bug to report |
| `ERR_WEBEID_VERSION_INVALID` | the developer | the application reported a malformed version; a bug to report |
| `ERR_WEBEID_UNKNOWN_ERROR` | the developer | anything else |

The codes are web-eid.js 2.x's, taken from its `ErrorCode` at 2.1.0; the server
and TLS codes of version 1 no longer exist. There is no code for a missing card
or a blocked PIN, because the Web eID application shows those in its own dialog.
What the page receives once the person closes that dialog is most likely
`ERR_WEBEID_USER_CANCELLED`, or `ERR_WEBEID_USER_TIMEOUT` if they leave it open;
that has not been tried on a card.

```js
allkiri.cardLogin({ challengeUrl: '/api/card/challenge', loginUrl: '/api/card/login' })
  .then(showTheUser)
  .catch(function (error) {
    var problem = allkiri.describeWebEidError(error);
    console.warn(error);
    showMessage(problem ? problem.text : 'Signing in did not work. Try again.');
  });
```

## Production trust

`Environment::production()` reaches its trust anchors through the European list
of trusted lists rather than any list pinned by hand:

1. the list of lists is verified against the certificates the Official Journal
   publishes, which are the only trust material shipped with this library;
2. it says where the Estonian list lives and which certificates may sign it;
3. the Estonian list is verified against those, and its services become the
   trust anchors.

A national list can change its signing certificate without this library needing
a release. Only the first step is pinned, and
[resources/trust/eu/README.md](../resources/trust/eu/README.md) records where
those certificates came from and how to check them against the Journal. Do check
them: they decide what your application treats as a qualified signature.

To follow other countries' lists as well:

```php
$environment = Environment::production()->withListOfLists(Environment::euListOfLists(['EE', 'LV', 'LT']));
```

Loading needs the network, and a failure to load is raised rather than swallowed:
an empty trust store would reject every signature for a confusing reason.

## Testing

`tests/Unit/WebEid` builds real authentication tokens with a test key rather
than replaying captured ones, so changing the origin or the challenge genuinely
stops them verifying. The signing tests stand in for the browser, reporting what
a card supports and then signing the digest as the card would, and produce full
containers for elliptic-curve and RSA keys in both paddings.

`tests/Integration/ListOfListsLiveTest.php` walks the production trust chain
against the live European and Estonian services. It fails if the list of lists
is signed by something this library does not ship, which is the warning that the
Journal has published a new set.

There is no automated integration test for a card: that needs a physical card,
a reader and a person. The checklist in
[manual-testing.md](manual-testing.md) covers it.

## A workaround you can delete one day

Estonian cards sign with ECDSA, and the signature arrives as raw r‖s with each
half padded to the width of the curve. About one half in 256 therefore begins
with a zero byte, and the official validation library's conversion of that to
DER keeps the zero even when it is superfluous, which is not valid DER. OpenSSL
refuses it, so roughly one authentication in 256 fails although the signature is
good. The person tries again and it works.

`WebEidAuthenticator` re-encodes the signature itself before handing the token
over, which avoids the broken path. Nothing else changes, and nothing that was
refused before is accepted now.

Remove it once a release of `web-eid/web-eid-authtoken-validation-php` contains
the fix for
[issue #71](https://github.com/web-eid/web-eid-authtoken-validation-php/issues/71),
which is pull request #74 and unreleased as of 1.3.1. The regression test named
in the code stays green either way, so removing the workaround is safe to try.
