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
2. **Signature structure.** A SignatureValue, a reference covering the signed
   properties, no `SignaturePolicyIdentifier` (that means BDOC-TM, which SK
   stopped supporting on 2023-11-01).
3. **Algorithms.** Digest and signature algorithms the policy allows, and a
   key large enough.
4. **The signing certificate.** The certificate in the signature is the one
   the signer committed to in the signed properties.
5. **References.** Every data file's digest matches, the signed properties'
   digest matches, every file in the container is covered, and each data
   reference has the media type BDOC requires.
6. **The signature value**, over the canonicalised SignedInfo.
7. **Timestamps.** The token covers this signature's value, verifies, and
   comes from a trusted timestamp authority. This establishes the *best
   signature time*: the moment the signature provably existed.
8. **The certificate chain**, as it stood at that moment, up to a trust anchor
   whose service was in a trustworthy status then.
9. **Revocation.** The embedded OCSP response answers about this certificate,
   was signed by an authorised responder, and says `good`.
10. **Order.** The revocation answer must not predate the timestamp; a gap
    beyond fifteen minutes warns and beyond a day fails.

## The policy

```php
$policy = new ValidationPolicy(
    allowedDigestAlgorithms: [HashAlgorithm::SHA256, HashAlgorithm::SHA512],
    minimumRsaKeyBits: 3072,
    ocspDelayWarningSeconds: 900,
);
$allkiri = new Allkiri(Environment::demo(), policy: $policy);
```

The defaults follow Estonian practice for BDOC 2.1.2: SHA-256 and above,
RSA-2048 and above, `DataObjectFormat` mandatory, the fifteen-minute and
one-day OCSP thresholds digidoc4j uses.

## Validating at a past moment

A signature valid today may not be valid in a decade, when the signer's
certificate has expired. That is exactly why LT signatures carry their
validation material. To re-check the decision as it stood:

```php
$report = $allkiri->validator()->validate($bytes, 'leping.asice', new ValidationOptions(
    validationTime: new DateTimeImmutable('2024-09-02T12:36:44Z'),
));
```

## A second opinion from SiVa

RIA runs a validation service. It is useful for comparing verdicts, and for
the formats allkiri does not read (DDOC, signed PDF):

```php
$siva = new SivaClient($allkiri->httpClient(), (string) $allkiri->environment()->sivaUrl);
$sivaReport = $siva->validate($bytes, 'leping.asice');
```

It sends the whole container, so do not point it at a service you would not
show the document to.

## Known differences from SiVa

| | allkiri | SiVa |
|---|---|---|
| Archive timestamps (LTA) | reported, not verified; warns | verified |
| BDOC-TM (time-mark) | `INDETERMINATE`, unsupported | validated |
| DDOC, PDF | not read | validated |
| CRL revocation data | reported, not checked | checked |

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

## A second opinion from SiVa

`SivaClient` sends a container to RIA's validation service, and `SivaComparison`
names the differences:

```php
$comparison = SivaComparison::of($ours, $siva->validate($bytes, 'leping.asice'));
if (!$comparison->agrees()) {
    $logger->warning($comparison->describe());
}
```

A difference is a question, not a verdict. SiVa is the reference for Estonian
practice, but it is a remote service with its own policy, its own trust-list
refresh cycle and its own clock. Nothing in allkiri's validation consults it,
and making SiVa's answer a condition of accepting a signature is a dependency to
take on deliberately. It also means sending the whole document to a third party.

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

The refusal is a `ZipBombException`, which is separate from the other reasons a
container cannot be read so that an application can tell a hostile upload from a
broken one. The declared size is checked first because it costs nothing, and an
archive that lies about it is stopped part way through decompressing, so the
memory a refusal costs is bounded by the allowance rather than by the payload.

**What is refused outright**: ZIP64 archives, multi-disk archives, encrypted
entries, compression methods other than store and deflate, and entries whose
data is truncated. The writer refuses the same shapes rather than producing
them: more than 65535 files, or any file or container of four gigabytes or more,
which the format cannot record without ZIP64.

**What is not guarded here.** Total upload size is your decision, and it belongs
in your application or your web server, where `upload_max_filesize` and
`post_max_size` already live. Signing or validating holds roughly three to four
times the file size in memory, so a 128 MB limit runs out at around 40 MB of
input.
