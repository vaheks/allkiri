# Trust

A signature is only as trustworthy as the list of certificate authorities you
decide to believe. allkiri's production default is the European list of trusted
lists; this page says what that rests on and how to choose otherwise.

## Where anchors come from

An ETSI TS 119 612 **trusted list**: an XML document a member state publishes,
naming every qualified trust service and its status over time. Estonia's is
published by RIA. allkiri parses it into anchors for three kinds of service:

- certificate authorities, to chain a signer's certificate to
- timestamp authorities, to believe a timestamp from
- OCSP responders, to believe a revocation answer from

A service that was `granted` when a signature was made stays trustworthy for
that signature even after its status changes, which is why the status history
is kept rather than just the current value.

The same holds for an OCSP responder the list names: its answer counts if the
service stood when the answer was produced. A responder whose service had been
withdrawn by then is judged like one no list names, and must have been
delegated by the certificate's own CA.

## What production trusts

`Environment::production()` takes its trust from the European list of trusted
lists, which the European Commission publishes to point at every member state's
list. allkiri accepts that list only when it is signed by a certificate that
chains back to the six the Official Journal of the European Union publishes for
it, and those six ship in `resources/trust/eu`. Each national list it points to,
Estonia's by default, is accepted only when it is signed by a certificate the
list of lists names for that country.

The Commission changes the certificates that sign the list of lists without
waiting for the Journal, through pivot lists, as its [pivot
explanation](https://ec.europa.eu/tools/lotl/pivot-lotl-explanation.html)
describes:
- a pivot names the new set and is signed with a certificate the old set
  trusts;
- the list of lists names each pivot, newest first, above the Journal
  publication they build on.

allkiri follows them:
- It verifies each pivot newer than the publication its six come from
  (`Environment::EU_OFFICIAL_JOURNAL_URL`), oldest first, against the set the
  one before gave, and verifies the list against the set that results. So a
  change of set needs no new release of allkiri.
- A pivot that cannot be fetched or does not verify is skipped with a warning,
  and adds nothing.
- A newest pivot that moves the list to another address is only reported.
- Pivots are cached for 30 days, since they never change.

One change still needs a release. When the Commission publishes a new set in the
Journal, it keeps the old publication and its pivots listed for a transition
period of at least 15 days, then drops them. From then on the chain from the
shipped six is gone. allkiri then warns, tries every pivot still listed, and
works only if one of them was signed with a certificate it already trusts. The
nightly `ListOfListsLiveTest` fails on the first day of that period, which is
the time to refresh `resources/trust/eu`.

Those six certificates are therefore the root of the trust decision, so check
them against the Journal rather than against this library.
[resources/trust/eu/README.md](../resources/trust/eu/README.md) names the
publication, gives the SHA-256 of each file, and shows the command that
computes it.

Other member states' lists are one argument away:

```php
$environment = Environment::production()->withListOfLists(
    Environment::euListOfLists(['EE', 'LV', 'LT']),
);
```

## Pinning a list yourself

A trusted list is signed, and a list you configure directly is accepted only
when it is signed by a certificate you named:

```php
$source = new TrustedListSource(
    'https://sr.riik.ee/tsl/estonian-tsl.xml',
    [Certificate::fromPem(file_get_contents('estonian-tsl-signer.pem'))],
);
$environment = Environment::production()->withTrustedListSources([$source]);
```

Without that pin, anyone who can answer for the URL could hand you their own
list of authorities: the pin is the trust decision. A list pinned this way is
trusted beside the list of lists. To trust only the lists you pin, drop the list
of lists too:

```php
$environment = Environment::production()
    ->withListOfLists(null)
    ->withTrustedListSources([$source]);
```

An environment with neither has no anchors at all. That is the safer failure:
an empty trust store fails loudly, a wrong one fails silently.

`Environment::demo()` is ready to use because RIA publishes the test list's
signing certificate, and allkiri bundles it.

## Caching

The list of lists and every national list beneath it are downloaded the first
time something needs trust, and kept for as long as that `Allkiri` object
lives. Without a PSR-16 cache, the next `Allkiri` downloads them again, which
under PHP-FPM usually means every request that signs, signs someone in or
validates. Give it a cache:

```php
$allkiri = new Allkiri($environment, cache: $psr16Cache);
```

The cache holds the XML, not parsed anchors, and the signature is re-verified
on every read. A poisoned cache cannot introduce a trust anchor. A list is
accepted only when its one signature sits directly under the root and covers
the whole list, so a signed list nested inside a forged one is refused.

A list is written to the cache when it is fetched, not again when it is read
from there, so the cache lifetime decides how soon a fresh copy is fetched.

## When a list cannot be loaded

`$allkiri->trustStore()->anchors()` throws `TrustedListException` when a list
cannot be fetched, verified or parsed, with a reason such as
`TRUSTED_LIST_TRANSPORT`. Signing refuses with a `SigningException` that
carries it as the previous exception, and signing people in fails as well.
Validation does not throw: each signature is reported `INDETERMINATE` with
`TRUST_ANCHORS_UNAVAILABLE` and the exception's message. The failure is not
remembered, so each signature tries to load the lists again, and with the
network down each one waits out the HTTP timeouts again.

## When a list is not renewed

Every trusted list names its next update, the date by which a newer one is due.
A list past that date may be missing a withdrawal published since, and so may
every list reached through a list of lists that is itself overdue. A list that
names no next update counts as overdue from the start.

Each anchor remembers the list it came from, so validation can say when a
signature rests on an overdue one. By default the anchors are still used, and
the signature carries a `TRUSTED_LIST_EXPIRED` warning naming the list and what
rested on it: the signer's certificate authority, a timestamp authority, or an
OCSP responder the list names directly. A responder the certificate's own CA
delegated to is vouched for by that CA's chain, and does not count.

A policy can refuse those anchors instead, once a grace period has passed:

```php
$policy = new ValidationPolicy(trustedListGraceSeconds: 7 * 86400);
```

Past the next update plus the grace period, the anchors are left out, and the
part of the signature that needed one is `INDETERMINATE` with
`TRUSTED_LIST_EXPIRED`, under the sub-indication a missing anchor gives:
`NO_CERTIFICATE_CHAIN_FOUND` for the CA, `NO_POE` for a timestamp authority,
`TRY_LATER` for a responder. `0` refuses them as soon as the date passes. An
anchor for the same certificate from elsewhere, such as one added with
`withExtraTrustAnchors()`, still serves; anchors added by hand never expire.

Only validation looks at this. Signing and signing people in keep using the
loaded list, and the loader logs a warning when the list it loads is overdue.
Expiry is judged at the validation time, against the lists loaded now. A
long-running process that loaded its trust store once keeps those lists until
it loads them again.

## Anchors a list does not carry

Estonian ID-cards issued from November 2025 are Thales cards under Zetes'
PKI. The Estonian trusted list names Zetes' `ESTEID2025` as a qualified CA
since 30 October 2025, so production trust needs nothing added. The test list
does not carry the Zetes test CAs, so `Environment::demo()` adds them as extra
anchors. Any other CA a list does not carry is added the same way:

```php
$environment = $environment->withExtraTrustAnchors([
    TrustAnchor::manual($certificate, ServiceType::CaQc, 'Some CA'),
]);
```

## What is trusted for what

An anchor is trusted for one kind of service only. A certificate authority
cannot vouch for a timestamp, and a timestamp authority cannot issue signing
certificates. allkiri enforces that: chains are built against the service type
the caller asks for.

Within a chain, each CA's own constraints hold too. A path length constraint
limits how many CA certificates may follow it, counted as RFC 5280 counts them,
so a CA that certifies its own new key under the same name does not use up a
level; a trust anchor's limit is held to as well. An intermediate whose key
usage leaves out keyCertSign cannot issue certificates. A chain that breaks
either is reported as `INDETERMINATE` with `CHAIN_CONSTRAINTS_FAILURE`, because
a conforming path through certificates the signature did not carry could still
exist.
