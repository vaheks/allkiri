# Signing

allkiri creates ASiC-E containers with XAdES-LT signatures: the format
DigiDoc4 opens and SiVa validates.

## The short version

```php
use Allkiri\Allkiri;
use Allkiri\Config\Environment;
use Allkiri\Container\AsicContainer;
use Allkiri\Container\DataFile;
use Allkiri\Crypto\PrivateKey;
use Allkiri\Signing\LocalKeySigner;

$allkiri = new Allkiri(Environment::demo());

$container = AsicContainer::create(
    DataFile::fromPath('/path/to/leping.pdf'),
);

$keyPair = PrivateKey::fromPkcs12(file_get_contents('seal.p12'), $password);
$result = $allkiri->signingService()->signWith($container, LocalKeySigner::fromKeyPair($keyPair));

file_put_contents('leping.asice', $allkiri->writer()->write($result->container));
```

`signWith()` only suits a key this process holds. Every Estonian eID means
puts a person in the middle, so signing is really two steps.

## The two steps

```php
// Request 1: build everything that gets signed.
$dataToBeSigned = $allkiri->signingService()->prepare($container, $signerCertificate);

// Hand the digest to the signer and store the session meanwhile.
$_SESSION['signing'] = json_encode($dataToBeSigned);
$digestForTheCard = $dataToBeSigned->digestBase64();

// Request 2: the value comes back.
$dataToBeSigned = DataToBeSigned::fromJson($_SESSION['signing']);
$result = $allkiri->signingService()->finalize($container, $dataToBeSigned, $signatureValue);
```

`DataToBeSigned` is a plain value object that serialises to JSON, so a session,
a database column or a queue message all work. It holds nothing secret.

What `finalize()` does before spending anything:

1. Checks the container's data files are still the ones that were prepared.
2. Checks the container has not gained another signature meanwhile.
3. Verifies the completed signature against the container. This proves in one
   step that the prepared document was not altered, that it still covers
   exactly these files, and that the value really is a signature over it.

Only then does it buy a timestamp and ask for a revocation answer. A wrong
signature value costs nothing.

### Signature values

ECDSA values are accepted in either form: the raw `r‖s` that Web eID,
Mobile-ID and Smart-ID return, or the DER that OpenSSL and some card
middleware produce. RSA values are passed through as they are.

## Levels

| Level | What it adds | When |
|---|---|---|
| `B` | the signature alone | when a timestamp cannot be obtained; not enough for a qualified signature |
| `T` | a timestamp: proof of when | rarely on its own |
| `LT` | the certificates and revocation data needed to validate it years later | the default, and what Estonian practice expects |

```php
$options = (new SigningOptions())->withLevel(SignatureLevel::T);
```

Level LTA (archive timestamps) is not implemented yet.

The order inside LT is not negotiable: the timestamp is taken first, then the
revocation answer, so the answer provably comes after the signature existed.
allkiri refuses to build a signature whose OCSP response is older than its
timestamp, and warns when the gap exceeds fifteen minutes, which is where
validators start to complain.

## Choosing the algorithm

By default the signer's key decides: a P-256 key signs with ES256, a P-384 key
with ES384, an RSA key with RS256. Override it when the signing service
demands something else, as Smart-ID does with RSA-PSS:

```php
$options = (new SigningOptions())->withAlgorithm(SignatureAlgorithm::PS256);
```

## Adding a signature to an existing container

```php
$container = $allkiri->reader()->readFile('leping.asice');
$result = $allkiri->signingService()->signWith($container, $secondSigner);
```

The original entries are copied byte for byte, so the first signature stays
valid. The new signature goes into the next free `META-INF/signatures{N}.xml`.

## What ends up in the container

- `mimetype`, first and uncompressed, as ASiC-E requires
- the data files
- `META-INF/manifest.xml` naming each file's media type
- `META-INF/signatures0.xml`, and one more file per further signature

Inside a signature: a reference per data file, a reference to the signed
properties, the signing time, a `SigningCertificateV2` commitment to the
signer's certificate, a `DataObjectFormat` media type per file (BDOC requires
it), then the timestamp, the certificate chain and the OCSP response.

## Services and what they cost

| | Demo (free) | Production |
|---|---|---|
| Timestamps | `http://tsa.demo.sk.ee/tsa` | `http://tsa.sk.ee`, contract with SK |
| Revocation | `http://demo.sk.ee/ocsp` and the AIA responders | the AIA responder each certificate names is free; `ocsp.sk.ee` needs a contract |

By default allkiri asks the responder the certificate itself names in its
Authority Information Access extension. Override that per issuing CA when you
have a contract endpoint:

```php
$environment = Environment::production()->withOcspUrlOverrides([
    'C=EE, O=SK ID Solutions AS, CN=ESTEID2018' => 'http://ocsp.sk.ee',
]);
```

## Before production

`Environment::production()` deliberately trusts nothing until you pin the
Estonian trusted list's signing certificates. That pin is the trust decision;
see [trust.md](trust.md).
