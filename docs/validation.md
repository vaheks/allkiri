# Validation

```php
$report = $allkiri->validator()->validateFile('leping.asice');

if ($report->isValid()) {
    // every signature is TOTAL-PASSED
}

foreach ($report->signatures as $signature) {
    echo $signature->signedBy(), ': ', $signature->indication->value, "\n";
    foreach ($signature->errors() as $error) {
        echo '  ', $error->code, ': ', $error->message, "\n";
    }
}
```

The whole report serialises to JSON, in the shape SiVa's simple report uses.

## The three verdicts

allkiri reports what ETSI EN 319 102-1 defines and SiVa and DigiDoc4 also use.

| Indication | Meaning | Examples |
|---|---|---|
| `TOTAL-PASSED` | the signature is valid | |
| `TOTAL-FAILED` | something is provably wrong | a changed file, a broken signature, a revoked certificate |
| `INDETERMINATE` | nothing is provably wrong, but something needed to decide is missing | an unknown CA, no revocation data, an unverifiable timestamp |

The distinction matters. A signature made with a perfectly good certificate
from a CA you have not configured is `INDETERMINATE`, not invalid: the problem
is on your side. Treating it as a forgery would be wrong.

Each non-passing signature also carries a `subIndication` saying which check
failed, and findings with stable codes. Branch on the codes, show the messages.

## What is checked, in order

1. **Container structure.** A ZIP with `mimetype` first and uncompressed, a
   manifest that matches the files present, at least one signature file.
2. **Signature structure.** A SignatureValue, a reference covering this
   signature's own signed properties, no `SignaturePolicyIdentifier` (that
   means BDOC-TM, which SK stopped supporting on 2023-11-01). The signed
   properties in the report are read from the element that reference resolves
   to and from nowhere else, so an untouched copy placed beside the signature
   cannot be digested while altered properties are reported.
3. **Algorithms.** Digest and signature algorithms the policy allows, and a
   key large enough. The signatures this signature rests on meet a floor too:
   see steps 7 to 9.
4. **The signing certificate.** The certificate in the signature is the one
   the signer committed to in the signed properties, and it is a certificate
   for signing: its key usage includes nonRepudiation, which ETSI EN 319 412-2
   requires. An authentication certificate from the same CA does not qualify;
   such a signature is `INDETERMINATE` with `CHAIN_CONSTRAINTS_FAILURE`, as
   SiVa reports it.
5. **References.** Every same-document reference names an `Id` that exactly
   one element carries, every data file's digest matches, the signed
   properties' digest matches, every file in the container is covered, and
   each data reference has the media type BDOC requires.
6. **The signature value**, over the canonicalised SignedInfo.
7. **Timestamps.** The token covers this signature's value, verifies, and
   comes from a trusted timestamp authority whose certificate marks its
   timestamping purpose critical, as RFC 3161 requires. This establishes the
   *best signature time*: the moment the signature provably existed. A
   signature with no timestamp is `INDETERMINATE` with `NO_POE` and
   `TIMESTAMP_MISSING`, unless the policy's `requireSignatureTimestamp` is off.
8. **The certificate chain**, as it stood at that moment, up to a trust anchor
   whose service was in a trustworthy status then. Every CA in it keeps to its
   path length constraint, counted as RFC 5280 counts it, and every intermediate
   is allowed to sign certificates. A chain that breaks either is
   `INDETERMINATE` with `CHAIN_CONSTRAINTS_FAILURE`. The anchor's trusted list
   is checked as well: past its next update it gives a `TRUSTED_LIST_EXPIRED`
   warning, or, beyond the policy's `trustedListGraceSeconds`, the anchor is not
   trusted. The same holds for the timestamp authorities of step 7 and for a
   responder a list names directly in step 9. See
   [When a list is not renewed](trust.md#when-a-list-is-not-renewed).
9. **Revocation.** The embedded OCSP response answers about this certificate,
   was signed by an authorised responder, and says `good`. When the signature
   carries several responses, a revoked one decides. Otherwise the newest one
   produced within the policy's OCSP window after the signature time is used,
   and the newest overall only when none falls inside the window.
10. **Order.** The revocation answer must not predate the timestamp; a gap
    beyond fifteen minutes warns and beyond a day fails. When no timestamp
    verifies, the answer is held to the signer's claimed signing time instead:
    produced after it, within the same one-day window, and not after the
    validation time. Otherwise `REVOCATION_NOT_BOUND_TO_SIGNING_TIME`,
    `INDETERMINATE` with `NO_POE`, names the bound that failed.

In steps 7 to 9, every signature involved must be made with an acceptable
algorithm: the timestamp token, each certificate in a chain, the OCSP response
and a delegated responder's certificate. SHA-1 is refused whatever the policy
allows for references, and so is an RSA key below `minimumRsaKeyBits`. Either
finding is `INDETERMINATE` with `CRYPTO_CONSTRAINTS_FAILURE_NO_POE`, not
`TOTAL-FAILED`: nothing was forged, but nothing shows the signature was made
while its algorithm still counted. A certificate whose two signature algorithm
fields differ, which RFC 5280 forbids, is not treated as signed at all.

RSASSA-PSS is verified there as well, in the profile certificate authorities
issue: SHA-256, SHA-384 or SHA-512, MGF1 with the same hash, and a salt as long
as the digest. Other parameters are an algorithm allkiri does not support.

Steps 7 to 10 need the trust anchors. When they cannot be loaded, because a
trusted list cannot be fetched, verified or parsed, validation does not throw.
Each signature is `INDETERMINATE` with `NO_CERTIFICATE_CHAIN_FOUND` and
`TRUST_ANCHORS_UNAVAILABLE`, whose message gives the reason. What steps 1 to 6
found still stands, so a tampered container is still `TOTAL-FAILED`.

### Where the trust anchors come from

With `Environment::production()`, the anchors come from the European list of
trusted lists and the national lists it points to, verified as
[trust.md](trust.md) describes. They are downloaded the first time a signature
needs them, not when `Allkiri` is built, and kept for as long as that `Allkiri`
object lives. So the first validation in a process is the slow one, and the one
that reports `TRUST_ANCHORS_UNAVAILABLE` when the lists cannot be reached. A
failed download is not remembered: the next validation tries again.

Without a PSR-16 cache, each new `Allkiri` downloads them again, which under
PHP-FPM usually means every request that validates. Give it a cache, as
[trust.md](trust.md#caching) shows. `Environment::demo()` works the same way
with RIA's test list.

## The policy

```php
$policy = new ValidationPolicy(
    allowedDigestAlgorithms: [HashAlgorithm::SHA256, HashAlgorithm::SHA512],
    minimumRsaKeyBits: 3072,
    ocspDelayWarningSeconds: 900,
    trustedListGraceSeconds: 7 * 86400,
);
$allkiri = new Allkiri(Environment::demo(), policy: $policy);
```

The defaults follow Estonian practice for BDOC 2.1.2: SHA-256 and above,
RSA-2048 and above, `DataObjectFormat` mandatory, the fifteen-minute and
one-day OCSP thresholds digidoc4j uses, and a signature timestamp required. A
trusted list past its next update is only a warning until
`trustedListGraceSeconds` says how long to tolerate it.

`minimumRsaKeyBits` also sets the floor for the keys that sign the
certificates, OCSP responses and timestamps a signature rests on. A policy
given to `Allkiri` applies that floor when signing and signing people in, too.
`allowedDigestAlgorithms` governs only the signature's own references: SHA-1 is
refused beneath a signature whatever it says.

## Validating at a past moment

A signature valid today may not be valid in a decade, when the signer's
certificate has expired. That is exactly why LT signatures carry their
validation material. To re-check the decision as it stood:

```php
$report = $allkiri->validator()->validate($bytes, 'leping.asice', new ValidationOptions(
    validationTime: new DateTimeImmutable('2024-09-02T12:36:44Z'),
));
```

That moment changes less than the name suggests.

- **It changes** whether a trusted list counts as past its next update, and,
  for a signature whose timestamp does not verify, the latest moment an OCSP
  response may have been produced. The report records it as the validation
  time.
- **It does not change** how the signer's certificate, its chain and the
  revocation answer are judged. Those are always judged at the moment the
  signature is proven to have existed: its timestamp's time, or the signing
  time it claims when no timestamp verifies. That is the same with or without a
  validation time.
- **The trust anchors are today's.** The trusted lists are the ones loaded now.
  A service that has changed status since is judged by the status history the
  list keeps, not by the list as it stood on that day.

## A second opinion from SiVa

RIA runs a validation service. It is useful for comparing verdicts, and for
the formats allkiri does not read (DDOC, signed PDF). `SivaClient` sends it a
container, and `SivaComparison` names the differences:

```php
$ours = $allkiri->validator()->validate($bytes, 'leping.asice');
$siva = new SivaClient($allkiri->httpClient(), (string) $allkiri->environment()->sivaUrl);

$comparison = SivaComparison::of($ours, $siva->validate($bytes, 'leping.asice'));
if (!$comparison->agrees()) {
    $logger->warning($comparison->describe());
}
```

A difference is a question, not a verdict. SiVa is the reference for Estonian
practice, but it is a remote service with its own policy, its own trust-list
refresh cycle and its own clock. Nothing in allkiri's validation consults it,
and making SiVa's answer a condition of accepting a signature is a dependency to
take on deliberately.

It sends the whole container, so do not point it at a service you would not
show the document to. For the same reason the URL must be HTTPS; plain HTTP is
accepted only to `localhost`, `127.0.0.1` or `[::1]`.

When SiVa cannot give a verdict, `validate()` throws `SivaException`, and its
`reason` says why:

| `reason` | Meaning |
|---|---|
| `SIVA_REQUEST_INVALID` | the request could not be built, such as a file name that is not UTF-8; nothing was sent |
| `SIVA_TRANSPORT` | SiVa could not be reached |
| `SIVA_CHALLENGED` | bot protection answered instead of SiVa |
| `SIVA_HTTP_STATUS` | SiVa answered with an error status, quoted in the message |
| `SIVA_MALFORMED` | the answer was not a validation report |

RIA's SiVa sits behind Cloudflare since 2026, which now and then answers a
server with a challenge page meant for a browser. allkiri recognises it by the
`cf-mitigated: challenge` header Cloudflare sets and reports `SIVA_CHALLENGED`
without the page. It does not retry: asking again a little later usually works,
and a server that is refused every time needs RIA to let it through.

## Known differences from SiVa

| | allkiri | SiVa |
|---|---|---|
| Archive timestamps (LTA) | verified; not yet taken as proof that the signature existed before an algorithm weakened | verified |
| BDOC-TM (time-mark) | `INDETERMINATE`, unsupported | validated |
| DDOC, PDF | not read | validated |
| CRL revocation data | reported, not checked | checked |
| SHA-1 in a chain, an OCSP response or a timestamp | `INDETERMINATE` | a warning, for BDOC |
| A signature without a timestamp (level B) | `INDETERMINATE`, `TIMESTAMP_MISSING`; judged on its claimed time with `requireSignatureTimestamp: false` | not accepted for ASiC-E |
| A trusted list past its next update | a warning; `INDETERMINATE` beyond `trustedListGraceSeconds` | fails |

Where both validate the same signature, they should agree. The integration
suite compares them on every run.

## Reading a report

The report is built for programs: stable codes, ETSI indications, a JSON shape
that mirrors SiVa's. For a log or a support ticket:

```php
use Allkiri\Validation\Report\ReportRenderer;

echo ReportRenderer::summary($report);   // Valid: signed by JAAK-KRISTJAN JOEORG
echo ReportRenderer::text($report);      // a few lines per signature
```

Neither is part of the verdict, and an application showing its own wording
should read the findings rather than parse these lines.

## Containers that are hostile rather than invalid

A validator usually takes its input from a stranger, so some containers are not
merely wrong but designed to hurt. The reader refuses those before the validator
ever sees them, because the cost is paid during reading.

**Expansion.** A few hundred kilobytes of zeros can declare hundreds of
megabytes. Reading such a container held 406 MB of memory in under a second
before this guard existed, which is a handful of uploads away from taking a
server down. The rule is digidoc4j's, so the two libraries refuse the same
archives: expansion is unquestioned up to a threshold, and beyond it the whole
container may not exceed its own size times a ratio.

| | Default |
|---|---|
| Ratio checked above | 1 MB unpacked |
| Maximum unpacked to packed | 100 to 1 |

Ordinary documents are nowhere near that. Text compresses about five to one, and
PDFs and images barely compress at all. Change it when you know better:

```php
$allkiri = new Allkiri($environment, reader: new AsicReader(maxCompressionRatio: 500));
```

The refusal is `Allkiri\Container\ZipBombException`, an
`InvalidContainerException` kept separate from the other reasons a container
cannot be read so that an application can tell a hostile upload from a broken
one. The declared size is checked first because it costs nothing, and an
archive that lies about it is stopped part way through decompressing, so the
memory a refusal costs is bounded by the allowance rather than by the payload.

**A DTD, in any encoding.** A signature file, a manifest or a trusted list that
declares a DTD is refused, so none of them can define entities. The check runs on
the parsed document, because a search of the bytes for `<!DOCTYPE` misses UTF-16,
where a zero byte sits between the characters. Such a document's entities have
already been expanded by the time it is refused, within libxml2's own limits on
expansion. Refusing every encoding other than UTF-8 would avoid that, and was
left out so that UTF-16 documents stay readable.

**What is refused outright**: ZIP64 archives, multi-disk archives, encrypted
entries, compression methods other than store and deflate, and entries whose
data is truncated. The writer refuses the same shapes rather than producing
them: more than 65535 files, or any file or container of four gigabytes or more,
which the format cannot record without ZIP64.

**An archive that readers could read differently.** Two entries with one name
are refused, data files and `META-INF` entries alike. Readers do not agree on
which of the two counts, so a validator that checked one while DigiDoc4 or an
unzip tool shows the other would have reported on the wrong document.
libdigidocpp refuses the same archives. Also refused:

- an entry whose local header gives a different name from the central
  directory, since that name is what a streaming reader sees;
- an entry whose name an unzip tool would place outside the folder it extracts
  to, or that no file system holds: an absolute path, a `..` segment, a
  backslash, or a NUL byte, wherever in the archive the entry sits;
- an entry whose content does not match its CRC-32, which goes further than
  libdigidocpp or digidoc4j check.

All of these are an `InvalidContainerException`, reported as
`NOT_A_CONTAINER`. A manifest that lists one file twice is a failing
`MANIFEST_MISMATCH`.

**Nesting.** ASN.1 structures are refused when they nest more than 64 levels
deep. That covers certificates, OCSP responses and timestamp tokens, whether
they come from a container or from the network. phpseclib, which decodes them,
copies each level's content, so twenty thousand levels in about 80 KB exhaust a
128 MB memory limit. That is a fatal error, which no application can catch.

The check follows phpseclib's own decoder step for step. It also covers the
certificate extension values and public keys that phpseclib decodes a second
time. Apart from this depth limit, it refuses nothing phpseclib accepts, except
crafted input too intricate to walk within a budget proportional to its size.
Real structures nest a few dozen levels at most.

**Parts that do not parse.** Something inside an OCSP response or a timestamp
token that is not a certificate, a token claiming more than one signer, and a
certificate whose public key cannot be loaded are each reported as a finding
against the revocation answer, the timestamp or the signing certificate. None of
them escapes the validator as an exception, and the OCSP and timestamp clients
report them as a malformed response or an unsupported algorithm.

**What is not guarded here.** Total upload size is your decision, and it belongs
in your application or your web server, where `upload_max_filesize` and
`post_max_size` already live. Signing or validating holds roughly three to four
times the file size in memory, so a 128 MB limit runs out at around 40 MB of
input.
