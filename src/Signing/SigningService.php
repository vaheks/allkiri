<?php

declare(strict_types=1);

namespace Allkiri\Signing;

use Allkiri\Container\AsicContainer;
use Allkiri\Container\SignatureFile;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\CryptoException;
use Allkiri\Crypto\EcdsaSignature;
use Allkiri\Crypto\KeyType;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Xades\Dsig\XmlDsigVerifier;
use Allkiri\Xades\LtaExtender;
use Allkiri\Xades\LtExtender;
use Allkiri\Xades\SignatureBuilder;
use Allkiri\Xades\SignatureCompleter;
use Allkiri\Xades\SignatureDocument;
use phpseclib3\Crypt\EC;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;

/**
 * Creates signatures in two halves, because every eID means except a local key
 * puts a person between them.
 *
 * `prepare()` builds everything that is signed and returns the digest;
 * `finalize()` takes the value back, checks it, and completes the signature to
 * the requested level.
 */
final class SigningService
{
    public function __construct(
        private readonly ClockInterface $clock,
        private readonly ?LtExtender $ltExtender = null,
        private readonly ?LtaExtender $ltaExtender = null,
        private readonly ?SignatureBuilder $builder = null,
        private readonly SignatureCompleter $completer = new SignatureCompleter(),
        private readonly XmlDsigVerifier $dsigVerifier = new XmlDsigVerifier(),
        private readonly ?LoggerInterface $logger = null,
    ) {}

    /**
     * Build everything that is signed and return what the signer must sign.
     */
    public function prepare(AsicContainer $container, Certificate $signer, SigningOptions $options = new SigningOptions()): DataToBeSigned
    {
        if ($options->level !== SignatureLevel::B && $this->ltExtender === null) {
            throw new SigningException(\sprintf('Signing at level %s needs a timestamp and OCSP service; none is configured', $options->level->value));
        }
        $algorithm = $options->signatureAlgorithm ?? SignatureAlgorithm::forKey($signer->publicKey());
        $built = $this->builder()->build($container->dataFiles, $signer, $algorithm, $options->profile);

        return new DataToBeSigned(
            $built->signatureId,
            $container->nextSignatureFileName(),
            $algorithm,
            $built->digest(),
            $built->signedInfoCanonical,
            $built->document->toXml(),
            $signer,
            $container->fingerprint(),
            $options->level,
            $this->clock->now(),
        );
    }

    /**
     * Complete a prepared signature with the value the signer produced.
     *
     * @param string $signatureValue raw r‖s or DER for ECDSA; PKCS#1 or PSS bytes for RSA
     */
    public function finalize(AsicContainer $container, DataToBeSigned $dataToBeSigned, string $signatureValue): SigningResult
    {
        if ($container->fingerprint() !== $dataToBeSigned->containerFingerprint) {
            throw new SessionMismatchException('The container\'s data files changed since the signature was prepared');
        }
        if ($container->nextSignatureFileName() !== $dataToBeSigned->signatureFileName) {
            throw new SessionMismatchException(\sprintf('The container expects "%s" but the session was prepared for "%s"', $container->nextSignatureFileName(), $dataToBeSigned->signatureFileName));
        }

        $document = SignatureDocument::parse($dataToBeSigned->signatureXml);
        $signature = $document->signature($dataToBeSigned->signatureId) ?? throw new SessionMismatchException('The prepared document has no such signature');

        $value = $this->normalise($signatureValue, $dataToBeSigned);
        $this->completer->setSignatureValue($document, $dataToBeSigned->signatureId, $value);

        // Verify the finished signature against the container before spending
        // anything on a timestamp or an OCSP request. This proves in one step
        // that the prepared document was not altered between the two requests,
        // that it still covers exactly these data files, and that the value the
        // signer produced really is a signature over it.
        $resolver = new ContainerReferenceResolver($container);
        $verification = $this->dsigVerifier->verify($signature, $resolver, $dataToBeSigned->signerCertificate);
        foreach ($verification->references as $reference) {
            if (!$reference->isValid()) {
                throw new SessionMismatchException(\sprintf('The prepared signature no longer matches what it covers: reference "%s" %s', $reference->uri, $reference->problem ?? 'has the wrong digest'));
            }
        }
        if (!hash_equals($dataToBeSigned->signedInfoCanonical, $verification->signedInfoCanonical)) {
            throw new SessionMismatchException('The prepared signature changed between preparing and finalizing');
        }
        if (!$verification->signatureValid) {
            throw new InvalidSignatureValueException('The signature value does not verify against the signer\'s certificate');
        }

        $timestampTime = null;
        $ocspProducedAt = null;
        $warnings = [];
        $level = SignatureLevel::B;
        if ($dataToBeSigned->level !== SignatureLevel::B) {
            $extender = $this->ltExtender ?? throw new SigningException('No timestamp and OCSP service is configured');
            // LTA is reached through LT: the archive timestamp covers the
            // signature timestamp and the revocation data, so those have to
            // exist first.
            $ltLevel = $dataToBeSigned->level === SignatureLevel::LTA ? SignatureLevel::LT : $dataToBeSigned->level;
            $extension = $extender->extend($document, $signature, $dataToBeSigned->signerCertificate, $ltLevel);
            $timestampTime = $extension->timestampTime;
            $ocspProducedAt = $extension->ocspProducedAt;
            $warnings = $extension->warnings;
            $level = $extension->level;
        }
        if ($dataToBeSigned->level === SignatureLevel::LTA) {
            $lta = $this->ltaExtender ?? throw new SigningException('Signing at LTA needs an archive timestamp service; none is configured');
            $level = $lta->extend($document, $signature, new ContainerReferenceResolver($container))->level;
        }

        $this->logger?->info('Signed {file} at level {level}', ['file' => $dataToBeSigned->signatureFileName, 'level' => $level->value]);

        return new SigningResult(
            $container->withSignatureFile(new SignatureFile($dataToBeSigned->signatureFileName, $document->toXml())),
            $dataToBeSigned->signatureId,
            $dataToBeSigned->signatureFileName,
            $level,
            $timestampTime,
            $ocspProducedAt,
            $warnings,
        );
    }

    /**
     * Add an archive timestamp to a signature that is already in a container.
     *
     * This is how a signature is kept verifiable over time, and it is normally
     * done long after signing: before the algorithms or the certificates the
     * existing proof rests on weaken, a fresh timestamp is laid over the whole
     * assembly. It can be repeated, each one covering all the others.
     *
     * @param string|null $signatureFileName which signature file to archive;
     *                                       null archives every one in the container
     */
    public function archive(AsicContainer $container, ?string $signatureFileName = null): SigningResult
    {
        $lta = $this->ltaExtender ?? throw new SigningException('Archiving needs a timestamp service; none is configured');

        $files = $signatureFileName === null
            ? $container->signatureFiles
            : array_values(array_filter($container->signatureFiles, static fn(SignatureFile $f): bool => $f->name === $signatureFileName));
        if ($files === []) {
            throw new SigningException(\sprintf('The container has no signature file "%s"', $signatureFileName ?? ''));
        }

        $resolver = new ContainerReferenceResolver($container);
        $result = $container;
        $lastId = '';
        $lastName = '';
        $timestampTime = null;

        foreach ($files as $file) {
            $document = SignatureDocument::parse($file->xml);
            foreach ($document->signatures() as $signature) {
                $extension = $lta->extend($document, $signature, $resolver);
                $timestampTime = $extension->timestampTime;
                $lastId = $signature->getAttribute('Id');
            }
            $result = $result->withReplacedSignatureFile(new SignatureFile($file->name, $document->toXml()));
            $lastName = $file->name;
        }

        $this->logger?->info('Archived {file}', ['file' => $lastName]);

        return new SigningResult($result, $lastId, $lastName, SignatureLevel::LTA, $timestampTime);
    }

    /**
     * Prepare and finalize in one go, for signers that answer immediately.
     */
    public function signWith(AsicContainer $container, Signer $signer, SigningOptions $options = new SigningOptions()): SigningResult
    {
        $dataToBeSigned = $this->prepare($container, $signer->certificate(), $options);

        return $this->finalize($container, $dataToBeSigned, $signer->sign($dataToBeSigned));
    }

    /**
     * Accept whatever shape the signer produced and return the XML-DSig one.
     */
    private function normalise(string $signatureValue, DataToBeSigned $dataToBeSigned): string
    {
        if ($signatureValue === '') {
            throw new InvalidSignatureValueException('The signature value is empty');
        }
        if ($dataToBeSigned->algorithm->keyType() !== KeyType::EC) {
            return $signatureValue;
        }
        $key = $dataToBeSigned->signerCertificate->publicKey();
        if (!$key instanceof EC\PublicKey) {
            throw new InvalidSignatureValueException('The certificate has no elliptic-curve key for an ECDSA signature');
        }
        // Mobile-ID, OpenSSL and card middleware hand back DER; XML-DSig wants r‖s.
        try {
            return EcdsaSignature::toRaw($signatureValue, $key);
        } catch (CryptoException $exception) {
            throw new InvalidSignatureValueException($exception->getMessage(), 0, $exception);
        }
    }

    private function builder(): SignatureBuilder
    {
        return $this->builder ?? new SignatureBuilder($this->clock);
    }
}
