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
