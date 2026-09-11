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
