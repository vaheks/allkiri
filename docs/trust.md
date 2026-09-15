# Trust

A signature is only as trustworthy as the list of certificate authorities you
decide to believe. allkiri never decides that for you.

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

## The pin is the trust decision

A trusted list is signed. allkiri accepts one only when it is signed by a
certificate you named:

```php
$source = new TrustedListSource(
    'https://sr.riik.ee/tsl/estonian-tsl.xml',
    [Certificate::fromPem(file_get_contents('estonian-tsl-signer.pem'))],
);
$environment = Environment::production()->withTrustedListSources([$source]);
```

Without that, anyone who can answer for the URL could hand you their own list
of authorities. `Environment::production()` therefore ships with no sources at
all and trusts nothing until you add them. That is deliberate: an empty trust
store fails loudly, a wrong one fails silently.

`Environment::demo()` is ready to use because RIA publishes the test list's
signing certificate, and allkiri bundles it.

Where the production pin comes from: the EU list of trusted lists names the
certificates permitted to sign each member state's list. Verifying that chain
automatically is Phase 4 work; until then, take the certificate from the LOTL
and pin it yourself.

## Caching

The Estonian list is over a megabyte. Give allkiri a PSR-16 cache or it will
fetch it on every request:

```php
$allkiri = new Allkiri($environment, cache: $psr16Cache);
```

The cache holds the XML, not parsed anchors, and the signature is re-verified
on every read. A poisoned cache cannot introduce a trust anchor.

A list is written to the cache when it is fetched, not again when it is read
from there, so the cache lifetime decides how soon a fresh copy is fetched.

## When a list cannot be loaded

`$allkiri->trustStore()->anchors()` throws `TrustedListException` when a list
cannot be fetched, verified or parsed, with a reason such as
`TRUSTED_LIST_TRANSPORT`. Signing and signing people in fail the same way.
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
PKI, which the trusted lists do not yet list. `Environment::demo()` therefore
adds the Zetes test CAs as extra anchors. For production, add them the same way
once you have the production certificates from `https://repository.eidpki.ee/crt/`:

```php
$environment = $environment->withExtraTrustAnchors([
    TrustAnchor::manual($zetesCa, ServiceType::CaQc, 'ESTEID2025'),
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
