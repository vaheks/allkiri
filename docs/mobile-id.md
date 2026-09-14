# Mobile-ID

Mobile-ID puts a signing key on the person's SIM card. The library asks SK's
service to send them a request, the phone shows a four-digit verification code
and asks for a PIN, and the answer comes back as a signature.

Nothing here blocks by default. Both flows hand you a session you can store
between two HTTP requests, because the person may take half a minute to find
their phone.

## Configuring

```php
use Allkiri\Allkiri;
use Allkiri\Config\Environment;
use Allkiri\MobileId\MobileIdConfiguration;

$allkiri = new Allkiri(Environment::demo());
$configuration = MobileIdConfiguration::demo('Sign the lease');
```

In production the relying-party identifier and name come with your SK contract
and must match it exactly, or the service answers 401:

```php
$configuration = MobileIdConfiguration::production(
    $_ENV['MID_UUID'],
    $_ENV['MID_NAME'],
    'Sign the lease',
);
```

The demo service answers only for [SK's published test
numbers](https://github.com/SK-EID/MID/wiki/Test-number-for-automated-testing-in-DEMO).

### Display text

The text appears on the phone above the verification code. It is measured in
characters, not bytes:

| Format | Limit | Carries |
|---|---|---|
| `DisplayTextFormat::Gsm7` (default) | 100 characters, at most 5 from the extension table `€[]^\|{}\` | the GSM 03.38 alphabet, which includes `ä ö ü` but **not** `õ š ž` or Cyrillic |
| `DisplayTextFormat::Ucs2` | 50 characters | anything |

A character GSM-7 cannot carry is not refused by the service, it is **replaced
with a space**, so `Nõustun` would reach the phone as `N ustun`. The
configuration refuses such text instead and names the offending characters. Let
the library choose when the text is not fixed:

```php
$text = 'Nõustun tingimustega';
$configuration = MobileIdConfiguration::demo()
    ->withDisplayText($text, DisplayTextFormat::forText($text));
```

### Timeouts

`pollTimeoutMs` (default 10 000, maximum 60 000) is how long the service may
hold one status request open before answering. `sessionTimeoutSeconds`
(default 120) is how long the library keeps asking before giving up on the
person.

The HTTP client must be willing to wait longer than a single poll.
`Allkiri::mobileIdClient()` takes care of that; if you build `MobileIdClient`
yourself, size your client with `$configuration->httpTimeoutSeconds()`.

## Authenticating

```php
$authenticator = $allkiri->mobileIdAuthenticator($configuration);

$session = $authenticator->start(new MobileIdIdentity('+37200000766', '60001019906'));

// Show this immediately, and keep the session.
echo $session->verificationCode;     // "1462"
$_SESSION['mid'] = json_encode($session);
```

Then, from a browser poll a second or two apart:

```php
$session = MobileIdSession::fromJson($_SESSION['mid']);
$identity = $authenticator->poll($session);   // null while they are still deciding

if ($identity !== null) {
    $identity->identityCode;          // "60001019906"
    $identity->fullName();            // "MARY ÄNN O’CONNEŽ-ŠUSLIK TESTNUMBER"
    $identity->semanticsIdentifier(); // "PNOEE-60001019906" — use this as the account key
}
```

`poll()` throws `MobileIdSessionException` when the person cancelled, their
phone was unreachable, or the session timed out. Show `$exception->result->message()`,
and offer to try again when `$exception->result->isWorthRetrying()`.

### Two things SK asks of you, which no library can do for you

**Name yourself recognisably.** The relying-party name appears in bold at the
top of the dialog on the phone, and it is how the person tells your request
apart from an attacker's. SK does not accept generic names such as "login" or
"authentication": use your company name, your domain, or a brand the person
associates with the site they are on. The display text goes underneath, and is
the place for what is being signed, such as the document's name.

**Do not reveal who has Mobile-ID.** An authentication for someone with no
Mobile-ID still starts a session and only reports `NotMidClient` when polled,
so treating that differently in the interface turns your login form into a way
of mining who has Mobile-ID and who does not. SK's [secure implementation
guide](https://github.com/SK-EID/MID/wiki/Secure-Implementation-Guide) asks you
to show a verification code regardless and then fail the same way a timeout
fails:

```php
try {
    $session = $authenticator->start($identity);
    $code = $session->verificationCode;
} catch (CertificateNotFoundException) {
    $code = VerificationCode::random();   // indistinguishable from a real one
    $session = null;
}

echo "Verification code {$code}";

// Later, for both cases: "No such account, or nobody answered in time."
```

The same goes for the other failures. `MobileIdResult::message()` is written
for a person, but which of them you show is your decision, and the guide's
advice is one message for anything that did not succeed.

### What is actually checked

The verification code is the only thing standing between a person and
approving a session somebody else started in their name, so **show it before
they touch their phone**.

On the way back, the library refuses the answer unless all of this holds:

- the signature verifies against the certificate the service returned, over the
  random challenge this session generated;
- the certificate is valid at this moment;
- it chains to a trust anchor;
- the identity code in the certificate is the one the session was started for.

## Signing

The certificate must be known before the digest is built, so signing fetches it
first. That request does not involve the phone.

```php
$signer = $allkiri->mobileIdSigner($configuration);
$container = AsicContainer::create(DataFile::fromPath('leping.pdf'));

$signing = $signer->start($container, $identity);
echo $signing->verificationCode();
$_SESSION['signing'] = json_encode($signing);
```

Then:

```php
$signing = MobileIdSigningSession::fromJson($_SESSION['signing']);
$result = $signer->poll($container, $signing);   // null while they are still deciding

if ($result !== null) {
    file_put_contents('leping.asice', $allkiri->writer()->write($result->container));
}
```

The container you pass to `poll()` must be the same one you passed to
`start()`, down to the bytes of its data files; otherwise you get a
`SessionMismatchException` rather than a signature over something else.

Mobile-ID returns ECDSA values DER-encoded while XML-DSig needs `r‖s`. The
library converts, and verifies the finished signature against the certificate
before spending anything on a timestamp or an OCSP request.

## Blocking flows

A console tool or queue worker can wait:

```php
$identity = $authenticator->authenticate($identity);
$result = $signer->sign($container, $identity);
```

Both use `MobileIdPoller`, which long-polls within the session budget. Do not
use them in a web request: they hold the thread for as long as the person takes.

## Errors

| Class | Means |
|---|---|
| `CertificateNotFoundException` | no active Mobile-ID for this person and number |
| `MobileIdSessionException` | the person did not complete it; carries a `MobileIdResult` |
| `MobileIdApiException` | our fault or SK's: transport, a rejected request, an outage. Carries a `reason` constant and the HTTP status |
| `MobileIdException` | the answer did not hold up: wrong signature, wrong person, untrusted certificate |

`MobileIdResult` covers every outcome SK publishes: `Ok`, `Timeout`,
`NotMidClient`, `UserCancelled`, `SignatureHashMismatch`, `PhoneAbsent`,
`DeliveryError`, `SimError`. Each has an English `message()` fit to show a
user, and `isWorthRetrying()`.

## Testing

`tests/Unit/MobileId` runs the whole flow offline against a mock service that
holds a test key, so a full Mobile-ID LT container is built and validated
without touching the network.

`tests/Integration/MobileIdDemoTest.php` uses SK's published demo numbers and
needs `ALLKIRI_INTEGRATION=1`. It fetches a certificate, authenticates,
asserts that every documented failure number produces its own result, and signs
a container with both the ECC and the RSA demo number, checking the result with
our own validator and with SiVa. Set `ALLKIRI_ARTEFACTS` to a directory to keep
the containers for opening in DigiDoc4.
