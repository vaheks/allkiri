# Smart-ID

Smart-ID keeps the signing key in an app on the person's phone, split with a
server, so there is no SIM card and no reader. The library speaks version 3 of
SK's relying-party API.

Two things differ from Mobile-ID and are worth reading before you start.

**There are two families of flow.** A *notification* flow pushes the request to
a device the person has already registered with you, and you show them a code to
compare. A *device-link* flow gives you a link instead, which the person follows
from a QR code on screen or a tap on the same phone; an anonymous device-link
authentication names nobody, so whoever scans it identifies themselves. That is
the flow behind a plain "log in with Smart-ID" button.

**Smart-ID keys are RSA, and SK now wants RSASSA-PSS.** PKCS#1 v1.5 is
deprecated, so a Smart-ID container declares an RFC 6931 PSS signature method.
The library defaults to that and will not write a container whose declared
method does not match the signature it received.

## Configuring

```php
use Allkiri\Allkiri;
use Allkiri\Config\Environment;
use Allkiri\SmartId\SmartIdConfiguration;

$allkiri = new Allkiri(Environment::demo());
$configuration = SmartIdConfiguration::demo();
```

In production the relying-party identifier and name come with your SK contract:

```php
$configuration = SmartIdConfiguration::production($_ENV['SID_UUID'], $_ENV['SID_NAME']);
```

A service URL of your own, such as a mock, must be HTTPS. Plain HTTP is
accepted only to `localhost`, `127.0.0.1` or `[::1]`, because requests carry the
relying-party identifier and the person being asked for, and the configuration
refuses anything else.

The scheme name (`smart-id` or `smart-id-demo`) is not decoration. It is part of
what an authentication signs and part of every device link's authentication
code, so a demo configuration pointed at production fails verification instead
of quietly half-working. `demo()` and `production()` set it for you.

The relying-party name is what the person sees in bold on their phone, so it
must identify you: your company, your domain, or a brand they recognise. SK does
not accept generic names, and the limit is 32 characters.

### Certificate levels

| Level | Means |
|---|---|
| `CertificateLevel::Advanced` | a Smart-ID Basic account; the demo relying party has no access to these |
| `CertificateLevel::Qualified` | a qualified certificate (the default) |
| `CertificateLevel::Qscd` | qualified, with the key in a qualified signature creation device |

Ask for `Qscd` when you want a qualified electronic signature. The service
answers a `Qscd` request with a certificate it reports as `QUALIFIED`, which the
library treats as satisfying it.

A level passed to `startNotification()`, `startDeviceLink()` or
`startAnonymous()` replaces the configured one for that session. The session
remembers it, and the answer must satisfy it. The service reports the level
beside the signature rather than inside what was signed. So, as SK's own client
does, the library also requires the certificate to carry that level's
certificate policies:
- for qualified, SK's `1.3.6.1.4.1.10015.17.2` and ETSI's `0.4.0.2042.1.2`;
- for advanced, `1.3.6.1.4.1.10015.17.1` and `0.4.0.2042.1.1`.

### Interactions

An interaction is a dialogue you would like the app to show. You give a list in
order of preference; the app uses the first it understands and reports which.

```php
use Allkiri\SmartId\Interactions;

$interactions = Interactions::forText('Sign the lease with Allkiri OÜ?', 'Sign the lease');
```

`forText()` builds the three below, strongest first: the verification-code
choice, the confirmation message, then the PIN dialogue. The PIN dialogue holds
only 60 characters, so a longer sentence needs a shorter text for it, given as
the second argument as here; nothing is cut to fit. For any other list, build it
yourself:

```php
use Allkiri\SmartId\Interaction;

$interactions = Interactions::of(
    Interaction::confirmationMessage('Sign the lease with Allkiri OÜ?'),
    Interaction::displayTextAndPin('Sign the lease'),
);
```

| Interaction | Limit | Shows |
|---|---|---|
| `displayTextAndPin` | 60 characters | the plain PIN dialogue |
| `confirmationMessage` | 200 characters | a screen of its own for a longer sentence |
| `confirmationMessageAndVerificationCodeChoice` | 200 characters | the same, and then three codes of which only one matches yours |

The verification-code choice is the strongest protection against someone else
starting a session in the person's name, because a person who is not looking at
your page cannot guess which of the three to press. Offer it first for anything
that matters. Device-link flows cannot use it, and the library drops it from the
list for them rather than failing.

Limits are counted in characters, so accented letters cost one, not two.

### Pinning SK's TLS key

allkiri does not pin. It checks the service's certificate against the
certificate authorities your system trusts, as for any HTTPS request. SK asks
relying parties to pin the service's key as well ([HTTPS
pinning](https://sk-eid.github.io/smart-id-documentation/https_pinning.html)),
or to call only from addresses registered with SK. The library leaves the pin to
you because it has to follow every certificate change SK makes, and a pin that
falls behind stops the service. To pin, give a pinned HTTP client to the
Smart-ID client only, and build the authenticator and the signer on that
client:

```php
use Allkiri\Http\CurlHttpClient;
use Allkiri\SmartId\SmartIdAuthenticator;
use Allkiri\SmartId\SmartIdClient;
use Allkiri\SmartId\SmartIdSigner;

$http = new CurlHttpClient(
    $configuration->httpTimeoutSeconds(),
    pinnedPublicKeys: explode(' ', $_ENV['SID_TLS_PINS']),
);
$client = new SmartIdClient($configuration, $http);
$authenticator = new SmartIdAuthenticator($client, $allkiri->chainBuilder(), $allkiri->ocspClient());
$signer = new SmartIdSigner($client, $allkiri->signingService());
```

Do not pass a pinned client to `new Allkiri(...)`. That client also fetches the
trusted lists and talks to SiVa, and a pin for SK's host refuses every other
host, so production trust fails to load with `TRUSTED_LIST_TRANSPORT`.

A pin is the base64 SHA-256 of the key, with or without the `sha256//` prefix.
Compute it from the certificate SK publishes on that page:

```bash
openssl x509 -in rp-api.crt -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | openssl enc -base64
```

SK replaces the certificate when it expires, usually with a new key, and
announces it on its [news page](https://www.skidsolutions.eu/news/) a few weeks
ahead. A pin that is not updated in time stops every Smart-ID request with
`SmartIdApiException` and curl's "public key does not match pinned public key".
So keep the pins in configuration, list the old and the new one together until
the switch, and remove the old one afterwards.

## Authenticating

### With a notification

```php
$authenticator = $allkiri->smartIdAuthenticator($configuration);

$session = $authenticator->startNotification(
    SemanticsIdentifier::estonian('40504040001'),
    $interactions,
);

echo $session->verificationCode;      // show this immediately
$_SESSION['sid'] = json_encode($session);
```

Then, from a browser poll:

```php
// A SessionDataException here means the store handed back something that
// cannot be read as a session; start again.
$session = SmartIdSession::fromJson($_SESSION['sid']);
$identity = $authenticator->poll($session);   // null while they are still deciding

if ($identity !== null) {
    $identity->semanticsIdentifier();   // "PNOEE-40504040001" — the account key
    $identity->fullName();
}
```

Unlike Mobile-ID, the service does not hand back a verification code for an
authentication. Both sides derive it from the challenge, and the library does
that for you.

### With a QR code

```php
$session = $authenticator->startAnonymous($interactions);
$_SESSION['sid'] = json_encode($session);   // server side only, see below
```

A QR link carries how many seconds have passed since the session started, and
the app refuses a stale one, so the code has to be rebuilt about once a second.
The browser asks your server for each new link:

```php
$session = SmartIdSession::fromJson($_SESSION['sid']);
$link = $session->deviceLink($configuration->scheme, $configuration->relyingPartyNameBase64());

echo $link->url($session->sessionSecret, $session->elapsedSeconds());
```

> **The session secret must never reach the browser.** It is the key to the
> authentication code on every link for that session; anyone holding it can mint
> links the app will accept. Send the finished link, never the secret. The
> serialised session contains it, so keep that server-side too.

### On the same phone

A Web2App link opens the Smart-ID app on the phone the page is on, and the app
sends the person back to a callback URL of yours when they are done. SK
recommends it as the first option on a phone or a tablet, with the QR code as
the second, and the QR code alone on a computer. One session serves both, as
long as it is started with the callback URL:

```php
use Allkiri\SmartId\DeviceLink;
use Allkiri\SmartId\SmartIdCallback;

// Adds a random value, so that no two sessions share a callback URL.
$callbackUrl = SmartIdCallback::initialUrl('https://example.org/smart-id/callback');
$session = $authenticator->startAnonymous($interactions, initialCallbackUrl: $callbackUrl);
$_SESSION['sid'] = json_encode($session);

$link = $session->deviceLink($configuration->scheme, $configuration->relyingPartyNameBase64(), DeviceLink::TYPE_WEB2APP);
$web2App = $link->url($session->sessionSecret);   // built once, no elapsed seconds
```

Send the person to `$web2App`. For an app of your own, use
`DeviceLink::TYPE_APP2APP` with a callback URL your app handles. The session
keeps the callback URL: the app signs it, and the authentication code of every
Web2App and App2App link built from the session covers it. A QR link carries
none. If the app is missing or the browser will not hand the link over, SK's
fallback page explains what to do.

When the person has entered their PIN, the app opens the callback URL in a new
tab, with `sessionSecretDigest` and, for an authentication,
`userChallengeVerifier` added. Hand the whole query to `poll()`:

```php
// The session this browser started, found through its own cookie. The
// session cookie must be SameSite=Lax, or it does not come along.
$session = SmartIdSession::fromJson($_SESSION['sid']);
unset($_SESSION['sid']);   // a callback is accepted once

$identity = $authenticator->poll($session, SmartIdCallback::fromQuery($_GET));
```

The library checks what [SK's callback
rules](https://sk-eid.github.io/smart-id-documentation/rp-api/callback_urls.html)
ask for before it believes the answer:
- every parameter of the session's callback URL, the random value included,
  came back unchanged;
- `sessionSecretDigest` is the SHA-256 of this session's secret;
- `userChallengeVerifier` hashes to the user challenge the service reported;
- the answer itself holds up, as below.

A Web2App or App2App answer without a callback is refused.
`SmartIdSigner::poll()` and `complete()` take the callback in the same way for a
signature started with `startDeviceLink()` and a callback URL.

Two checks stay with you:
- **The browser.** The session must be the one this browser started, which is
  why it comes from `$_SESSION` rather than from anything in the URL.
- **Once only.** Forget the session when its callback arrives, so the same
  callback is never accepted twice.

If the app opens the callback in a browser other than the one the person
started in, which happens from an app's built-in browser, from a non-default
browser on iOS and in private mode, that browser has no session. Ask the person
to start again from their default browser.

SK may report the session finished before the callback arrives. If the page the
person started on keeps polling as well, for the QR code beside the link, a
same-device answer can reach that poll first, and without a callback it is
refused there. So ask the client for the status and leave an answer whose
`$status->flowType` is `Web2App` or `App2App` to the callback.

### What is actually checked

The app does not sign the challenge alone. It signs a pipe-joined payload naming
the scheme, both sides' random values, you, a digest of the dialogues you
offered, the one it actually showed, and how it was reached. The library rebuilds
that from the stored session and verifies over it, so an answer is refused
unless it belongs to *this* session on *this* service. It also refuses unless:

- the PSS parameters are the ones the declared signature method describes;
- the certificate is at least the level the session asked for, and carries the
  certificate policies of the level the service reported;
- the certificate is valid now and chains to a trust anchor;
- the certificate has not been revoked, which its OCSP responder is asked. SK's
  [response verification guidance](https://sk-eid.github.io/smart-id-documentation/rp-api/response_verification.html)
  asks relying parties to check this. `SmartIdConfiguration::withoutRevocationCheck()`
  turns it off, for a test environment whose responder cannot be reached;
- the certificate names a person by personal code, passport or identity card
  number, never an organisation or nobody at all;
- the account that answered is the one the session was started for, and the
  certificate belongs to that account;
- a user challenge verifier, if you supplied one, matches.

## Signing

The certificate must be known before the digest exists, and Smart-ID hands it
over only for a named account. So there are two starting points.

**If you know the document number** (stored when they first signed in), nothing
extra is needed:

```php
$signer = $allkiri->smartIdSigner($configuration->withCertificateLevel(CertificateLevel::Qscd));
$container = AsicContainer::create(DataFile::fromPath('leping.pdf'));

$signing = $signer->startNotification($container, new DocumentNumber($stored), $interactions);
echo $signing->verificationCode();
$_SESSION['signing'] = json_encode($signing);
```

**If you only know the person**, ask their device which account to use first.
That costs one interaction and yields the document number:

```php
$sessionId = $signer->chooseCertificate(SemanticsIdentifier::estonian('40504040001'));
// …poll $allkiri->smartIdClient($configuration)->sessionStatus($sessionId)…
$chosen = $signer->completeCertificateChoice($status);
$chosen->documentNumber;   // store this; no interaction is needed next time
```

Then finish as usual:

```php
$signing = SmartIdSigningSession::fromJson($_SESSION['signing']);
$result = $signer->poll($container, $signing);

if ($result !== null) {
    file_put_contents('leping.asice', $allkiri->writer()->write($result->container));
}
```

The container passed to `poll()` must be the one the signature was started for,
down to the bytes of its data files;
[signing.md](signing.md#between-the-two-requests) says where to keep it in
between.

`startDeviceLink()` is the same with a link instead of a notification.

The digest algorithm comes from the configuration
(`withSigningHashAlgorithm()`), and the signature method follows it: SHA-256
gives `PS256`, and so on. Passing `SigningOptions` with an explicit algorithm
overrides that, including `RS256` if you deliberately want the deprecated
PKCS#1 v1.5.

## Blocking flows

A console tool or worker can wait:

```php
$identity = $authenticator->authenticate($session);
$result = $signer->sign($container, $signing);
```

Both use `SmartIdPoller`, which long-polls within the session budget. Do not use
them in a web request. `SmartIdPoller::wait()` returns the final status whatever
it says: a refusal as the service reported it, and a `TIMEOUT` status when
`sessionTimeoutSeconds` passes first. `waitForSuccess()` throws
`SmartIdSessionException` for both. A signature must also be finalized within
`preparedSignatureTtlSeconds` of being prepared, ten minutes by default, so a
session timeout above 600 seconds needs that limit raised on the `Allkiri`
constructor too.

## Errors

| Class | Means |
|---|---|
| `SmartIdSessionException` | the person did not complete it; carries a `SmartIdEndResult` and, where the service says so, which dialogue they refused |
| `SmartIdApiException` | our fault or SK's: transport, a rejected request, an unknown account, an outage. Carries a `reason` constant and the HTTP status |
| `SmartIdException` | the answer did not hold up: wrong signature, wrong certificate level, untrusted certificate, unusable parameters |

`SmartIdEndResult` covers everything the service reports, each with an English
`message()` and `isWorthRetrying()`. A blocked account or an outdated app is not
worth retrying; a cancellation or a timeout is.

Two statuses are worth naming, because they look like failures and are not:

- **403** also means an `ADVANCED` request with a relying-party identifier that
  has no access to Smart-ID Basic accounts.
- **404** when starting a session means the person has no account of that kind;
  when polling, it means the session has been forgotten.

## Testing

`tests/Unit/SmartId` runs the whole flow offline against a mock service that
holds an RSA test key. The mock builds the authentication payload itself,
independently of the library, so the payload construction is genuinely tested.
Device links are pinned byte for byte, including the order of their query
parameters and the eight parts of what the authentication code covers.

`tests/Integration/SmartIdDemoTest.php` uses SK's published demo accounts and
needs `ALLKIRI_INTEGRATION=1`. It fetches a certificate, authenticates by
account and by person, asserts that each documented refusal arrives as its own
result, runs a certificate choice, and signs containers with SHA-256 and
SHA-512, checking both with our validator and with SiVa. Set `ALLKIRI_ARTEFACTS`
to keep the containers.

Device-link flows need someone to scan the code or tap the link, and SK's demo
service has a stand-in for that person. Post a link you built to
`https://sid.demo.sk.ee/mock/device-link`, with one of the `MOCK` accounts from
[SK's test account list](https://sk-eid.github.io/smart-id-documentation/test_accounts.html),
and the session ends as that account's row says:

```bash
curl -H 'Content-Type: application/json' https://sid.demo.sk.ee/mock/device-link \
  -d '{"documentNumber": "PNOEE-40404040009-MOCK-Q", "flowType": "QR", "deviceLink": "https://sid.demo.sk.ee/device-link?..."}'
```

Send it within a second or two of building the link. The service answers 200
either way, but it acts only on a fresh link with a correct authentication
code: a link a few seconds old leaves the session running, and a wrong code
ends it with `PROTOCOL_FAILURE`.

`SmartIdDemoTest` uses it with `PNOEE-40404040009-MOCK-Q`, and checks that:
- a sign-in through a QR code completes;
- a signature through a QR code is TOTAL-PASSED in our validator and in SiVa;
- a changed authentication code ends in `PROTOCOL_FAILURE`;
- a Web2App tap ends with SK reporting the session finished through Web2App,
  with a user challenge, and the library refuses that answer without a callback
  that belongs to the session.

For Web2App, the mock opens the callback URL from SK's servers, which cannot
reach a CI runner, so a successful return through the callback is checked by
hand, on a phone against a server the phone can reach. The link construction is
also pinned offline, byte for byte.
