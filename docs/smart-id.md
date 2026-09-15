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
use Allkiri\SmartId\Interaction;
use Allkiri\SmartId\Interactions;

$interactions = Interactions::of(
    Interaction::confirmationMessageAndVerificationCodeChoice('Sign the lease with Allkiri OÜ?'),
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

For Web2App and App2App, build the link once with
`DeviceLink::TYPE_WEB2APP` or `DeviceLink::TYPE_APP2APP` and no elapsed seconds,
and send the person to it.

> **The session secret must never reach the browser.** It is the key to the
> authentication code on every link for that session; anyone holding it can mint
> links the app will accept. Send the finished link, never the secret. The
> serialised session contains it, so keep that server-side too.

If you gave an `initialCallbackUrl`, the session keeps it: the app signs it, and
the authentication code of every Web2App and App2App link built from the session
covers it. A QR link carries none. The app returns a `userChallengeVerifier`
through the callback. Pass it to `poll()`, where a Web2App or App2App answer is
refused without it, and the library checks it against the session:

```php
$identity = $authenticator->poll($session, $_GET['userChallengeVerifier']);
```

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

Device-link flows are not covered there: completing one needs someone to scan a
code, and SK drives that through a mock service of their own. The link
construction is covered offline instead.
