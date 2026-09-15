# Logging and the audit trail

Two different logs, for two different questions.

| | Question it answers | Who writes it |
|---|---|---|
| The audit trail | who asked for what, and how did it end | your application |
| The HTTP transcript | what exactly did we send and receive | `LoggingHttpClient` |

You want both, and you want them separable, because the first is evidence and
the second is debugging.

## The audit trail is yours to write

This is the log that matters when a signature is disputed, and the library
cannot write it for you. It has no idea which of your users is signing, which
contract this is, or what your retention policy says. What it does give you is an
API where every stage is an explicit call in your own code, so there is a natural
place to log at each one.

The stages, for all four means:

| Stage | What to record |
|---|---|
| A session is started | the mean, the eID service's own session identifier, who it was started for |
| A verification code is shown | nothing new, unless you want to prove it was shown |
| Polling | nothing. Thousands of lines saying "still waiting" bury the ones that matter |
| It finished | the outcome, and for a refusal which refusal |
| A container is created | the file names and the container fingerprint, which is what a signature will cover |
| A signature is finished | the level reached, the timestamp time, the revocation time, any warnings |
| A container is validated | the verdict |

`examples/demo-app/app.php` does exactly this in about ten lines. Its `audit()`
helper adds two things to every record: a correlation identifier stable for one
browser session, and the mode, so a demo line can never be mistaken for a live
one.

Two fields are worth insisting on.

**The service's own session identifier.** SK sees that identifier too. When
something is disputed, it is what lets their support and your log talk about the
same event.

**The container fingerprint**, from `AsicContainer::fingerprint()`. It identifies
the exact set of files a signature will cover. Recording it at the moment a
signing session starts is what later proves that what was signed is what was
shown, and it is cheap: one digest over names, media types and content digests.

The two times on a `SigningResult` are the ones that decide whether a signature
stays valid, so log both:

```php
$this->logger->info('signed', [
    'level' => $result->level->value,             // B, T, LT or LTA
    'timestamp' => $result->timestampTime,        // when it is proven to have existed
    'revocationChecked' => $result->ocspProducedAt,
    'warnings' => $result->warnings,              // created, but with something to say
]);
```

An audit trail without an identity is not an audit trail, so this log contains
personal data by design. Retention, access and deletion are yours to decide, and
that is a reason to keep it separate from the transcript below rather than a
reason to water it down.

## The HTTP transcript comes free

Every remote call the library makes goes through the one `HttpClient` you hand
it: Mobile-ID, Smart-ID, timestamps, revocation checks and trusted lists. So one
wrapper sees all of them:

```php
use Allkiri\Http\CurlHttpClient;
use Allkiri\Http\LoggingHttpClient;

$http = new LoggingHttpClient(new CurlHttpClient(), $logger);
$allkiri = new Allkiri(Environment::production(), $http, logger: $logger);
```

Each call produces one record: method, URL, status, elapsed milliseconds, and the
size of each body. A call that throws is logged at warning level with the elapsed
time and the exception, and then rethrown untouched, which is usually the most
interesting line in the file. The exception's message names the URL without
identity codes too, so a logger that prints the exception does not undo the
rule below.

Two rules are built in, because getting them wrong is expensive rather than
untidy.

**Credentials are never logged, at any setting.** The Mobile-ID and Smart-ID
relying-party identifiers are shared secrets, and a Smart-ID session secret mints
device links that the app will accept for the whole session. Those values are
replaced with `[redacted]` wherever they appear, at any depth of a JSON body.

**Personal data is logged only when you ask.** By default no bodies are logged at
all, and identity codes are removed from the URLs that carry them, so
`/v3/signature/certificate/PNOEE-50001029996-MOCK-Q` is recorded as
`/v3/signature/certificate/PNOEE-[redacted]`. Session identifiers survive,
because they are what ties a line to one attempt.

When you do need the contents, `personalData: true` logs bodies and whole URLs:

```php
new LoggingHttpClient($inner, $logger, personalData: true, maxBodyBytes: 4096);
```

Understand what that log then holds: identity codes, phone numbers,
certificates, and the digests of documents people signed. It belongs in a
debugging session with a retention period, not in your permanent application log.
Bodies are still truncated, still have credentials removed, and anything that is
not text, such as a timestamp token or an OCSP response, is recorded as its size
and media type rather than as bytes. The whole URL goes on the log line only: a
failed call's exception is the one your application sees, and its message stays
redacted.

## What the library logs itself

`Allkiri` takes a PSR-3 logger and writes about a dozen milestones to it: a
signature reached its level, an archive timestamp was added, a trusted list
loaded, a trusted list is past its next update and is being used anyway, Web eID
authenticated someone, revocation checking is switched off. It is a record of
decisions, and most of it is worth alerting on rather than merely storing. The
warnings especially: a trusted list nobody has refreshed is a problem that starts
quietly.

None of these lines names a person. Web eID's says what kind of identity signed
in, `PNOEE-[redacted]`, and Mobile-ID's line for someone without a certificate
gives only what the service answered. Which person it was belongs in your audit
trail.

Pass the same logger to both and the three layers interleave in one file, which
is what the demo does.

## Exceptions that name a person

Exceptions reach your error log whether or not any of the above is set up, so
their messages follow the same rule. Every message that names a URL shows it
without identity codes: the cURL and PSR-18 transports, and the Mobile-ID,
Smart-ID, SiVa, timestamp, OCSP and trusted-list errors built on them. A PSR-18
client's own exception is named in the message rather than chained, because
Guzzle and Symfony put the whole URL into it.
`CertificateNotFoundException` does not name the person either; the identity it
was about is on its `identity` property, for code that needs it.

A few messages still name a person, because naming them is the diagnosis:

- **Sign-in answered by someone else.** Mobile-ID and Smart-ID refuse an answer
  from a person, account or certificate other than the one the session was
  started for, and the message names both sides.
- **Certificate errors.** Chain building, revocation and OCSP errors quote the
  certificate's subject. For a personal certificate that is the person's name
  and identity code.

If your error log must not hold personal data, catch `AllkiriException` where
it leaves the library and log its class, and its reason where it has one,
instead of the message.

## Where it goes

Anywhere, because it is PSR-3. Monolog to a file, to Postgres, to MySQL, to
syslog, or your framework's own logger. The library never chooses, never opens a
file, and never writes anything if you pass nothing.

`examples/demo-app/logger.php` is a complete PSR-3 implementation in thirty
lines, writing one JSON object per line. It exists to show the shape of a useful
record rather than to be used: a timestamp, a level, the message **template**
with its placeholders intact, and the context as structured data. Keeping the
template unfilled is what makes two thousand similar lines one query instead of a
text search.

It refuses to start if it cannot write, naming the path, rather than discovering
it once per line. A logger that fails per call emits a PHP warning per call, and
on a development machine with `display_errors` on that warning is written into
the HTTP response body ahead of the JSON. The browser then cannot read an answer
it was given, and a successful authentication surfaces as a failed one.

In the demo it is switched on by pointing `ALLKIRI_LOG` at a file:

```bash
ALLKIRI_LOG=/tmp/allkiri.log ALLKIRI_LOG_HTTP=1 php -S localhost:8080 -t examples/demo-app/public examples/demo-app/public/index.php
```

`ALLKIRI_LOG_HTTP=1` adds the transcript and `ALLKIRI_LOG_PERSONAL_DATA=1` lets
that transcript carry bodies and identity codes. Three switches rather than one
verbosity level, because they are three different decisions.

## What not to log, anywhere

- **Relying-party identifiers and Smart-ID session secrets.** Handled for you in
  the transcript; do not reintroduce them in your own records.
- **The serialised sessions themselves.** They carry the challenge, and for
  Smart-ID the session secret. They are for your session store, not your log.
- **PHP session identifiers.** A session identifier in a log is a credential in a
  log. The demo derives a separate correlation identifier instead.
- **PIN codes.** They never reach your server, from any of the four means. If one
  appears in a log, something is badly wrong.
