<?php

declare(strict_types=1);

namespace Allkiri\Validation;

use Allkiri\Container\AsicContainer;
use Allkiri\Container\MimeTypes;
use Allkiri\Container\SignatureFile;
use Allkiri\Crypto\Asn1\Asn1;
use Allkiri\Crypto\Asn1\Asn1Exception;
use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\Ocsp\CertStatus;
use Allkiri\Crypto\Ocsp\NonceMode;
use Allkiri\Crypto\Ocsp\OcspException;
use Allkiri\Crypto\Ocsp\OcspResponse;
use Allkiri\Crypto\Ocsp\OcspResponseVerifier;
use Allkiri\Crypto\Ocsp\OcspVerificationOptions;
use Allkiri\Crypto\Ocsp\OcspVerificationResult;
use Allkiri\Crypto\SignatureAlgorithm;
use Allkiri\Crypto\Tsp\TimestampException;
use Allkiri\Crypto\Tsp\TimestampToken;
use Allkiri\Crypto\Tsp\TimestampTokenVerifier;
use Allkiri\Signing\ContainerReferenceResolver;
use Allkiri\Signing\SignatureLevel;
use Allkiri\Trust\ChainBuilder;
use Allkiri\Trust\ChainBuildingException;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustStore;
use Allkiri\Validation\Report\Finding;
use Allkiri\Validation\Report\Indication;
use Allkiri\Validation\Report\SignatureInfo;
use Allkiri\Validation\Report\SignatureReport;
use Allkiri\Validation\Report\SignatureScope;
use Allkiri\Validation\Report\SubIndication;
use Allkiri\Xades\Dsig\Canonicalizer;
use Allkiri\Xades\Dsig\Xml;
use Allkiri\Xades\Dsig\XmlDsigVerifier;
use Allkiri\Xades\Lta\ArchiveTimestampData;
use Allkiri\Xades\Model\XadesSignature;
use Allkiri\Xades\Model\XadesSignatureParser;
use Allkiri\Xades\Ns;
use Allkiri\Xades\XadesException;

/**
 * Decides whether one XAdES signature in a container is valid, and says why
 * when it is not.
 *
 * It never throws on bad input: a report that explains the problem is the
 * product. The order of the checks matters, because the later ones need the
 * time the earlier ones establish.
 */
final class SignatureValidator
{
    public function __construct(
        private readonly TrustStore $trustStore,
        private readonly ValidationPolicy $policy = new ValidationPolicy(),
        private readonly XadesSignatureParser $parser = new XadesSignatureParser(),
        private readonly XmlDsigVerifier $dsigVerifier = new XmlDsigVerifier(),
        private readonly TimestampTokenVerifier $timestampVerifier = new TimestampTokenVerifier(),
        private readonly OcspResponseVerifier $ocspVerifier = new OcspResponseVerifier(),
        private readonly Canonicalizer $canonicalizer = new Canonicalizer(),
        private readonly ArchiveTimestampData $archiveTimestampData = new ArchiveTimestampData(),
    ) {}

    public function validate(AsicContainer $container, SignatureFile $file, \DOMElement $element, \DateTimeImmutable $validationTime, ?TrustStore $trustStore = null): SignatureReport
    {
        $store = $trustStore ?? $this->trustStore;
        $signature = $this->parser->parse($element);
        $findings = [];
        foreach ($signature->warnings as $warning) {
            $findings[] = Finding::warning(FindingCodes::SIGNATURE_MALFORMED, $warning);
        }

        $level = $this->levelOf($signature, $findings);
        $signer = $signature->signerCertificate();

        $this->checkStructure($signature, $findings);
        $this->checkAlgorithms($signature, $signer, $findings);
        $this->checkSigningCertificateReference($signature, $signer, $findings);
        $this->checkSigningCertificateUsage($signer, $findings);
        $this->checkReferences($container, $signature, $element, $signer, $findings);

        $timestamp = $this->checkTimestamps($signature, $store, $findings);
        $bestSignatureTime = $timestamp?->genTime();
        if ($bestSignatureTime === null && $signature->signingTime !== null) {
            $bestSignatureTime = $signature->signingTime;
            if ($level !== null && $level !== SignatureLevel::B) {
                $findings[] = Finding::warning(FindingCodes::NO_POE_CLAIMED_TIME_USED, 'No usable timestamp; the signer\'s claimed signing time is used instead');
            }
        }

        $ocsp = null;
        if ($signer !== null && $bestSignatureTime !== null) {
            $chain = $this->checkChain($signature, $signer, $bestSignatureTime, $store, $findings);
            if ($chain !== null) {
                $ocsp = $this->checkRevocation($signature, $signer, $chain, $bestSignatureTime, $store, $findings);
            }
        }
        if ($ocsp !== null && $timestamp !== null) {
            $this->checkTimestampOcspOrder($timestamp, $ocsp, $findings);
        }

        $archiveTime = $this->checkArchiveTimestamps($container, $element, $store, $timestamp, $findings);

        [$indication, $subIndication] = $this->verdict($findings);

        return new SignatureReport(
            $signature->id,
            $file->name,
            $indication,
            $subIndication,
            $level,
            $signature->signatureMethod,
            $findings,
            new SignatureInfo(
                $signature->signingTime,
                $bestSignatureTime,
                $timestamp?->genTime(),
                $ocsp?->producedAt(),
                $timestamp === null ? null : base64_encode($timestamp->tstInfo()->messageImprint),
                $signature->claimedRoles,
                $signature->productionPlace,
                $archiveTime,
            ),
            $this->scopes($container, $signature),
            $signer,
        );
    }

    /**
     * @param list<Finding> $findings
     */
    private function levelOf(XadesSignature $signature, array &$findings): ?SignatureLevel
    {
        if ($signature->signatureValue === null) {
            return null;
        }
        if ($signature->signatureTimestamps === []) {
            return SignatureLevel::B;
        }
        if ($signature->archiveTimestampCount > 0) {
            return SignatureLevel::LTA;
        }
        if ($signature->ocspValues !== [] || $signature->certificateValues !== []) {
            return SignatureLevel::LT;
        }

        return SignatureLevel::T;
    }

    /**
     * @param list<Finding> $findings
     */
    private function checkStructure(XadesSignature $signature, array &$findings): void
    {
        if ($signature->signatureValue === null) {
            $findings[] = Finding::error(FindingCodes::SIGNATURE_MALFORMED, 'The signature has no SignatureValue', Indication::TotalFailed, SubIndication::FormatFailure);
        }
        if ($this->policy->requireSignedPropertiesReference && $signature->signedPropertiesReference() === null) {
            $findings[] = Finding::error(FindingCodes::SIGNED_PROPERTIES_REFERENCE_MISSING, 'No reference covers the signed properties', Indication::TotalFailed, SubIndication::FormatFailure);
        }
        if ($signature->hasSignaturePolicyIdentifier) {
            $findings[] = Finding::error(FindingCodes::UNSUPPORTED_BDOC_TM, 'This is a BDOC-TM (time-mark) signature; SK stopped supporting the format on 2023-11-01 and allkiri does not validate it', Indication::Indeterminate, SubIndication::PolicyProcessingError);
        }
        if ($signature->crlValueCount > 0) {
            $findings[] = Finding::warning(FindingCodes::CRL_NOT_SUPPORTED, 'The signature carries CRL revocation data, which allkiri does not check');
        }
    }

    /**
     * @param list<Finding> $findings
     */
    private function checkAlgorithms(XadesSignature $signature, ?Certificate $signer, array &$findings): void
    {
        if (!Canonicalizer::supports($signature->canonicalizationMethod)) {
            $findings[] = Finding::error(FindingCodes::UNSUPPORTED_CANONICALIZATION, \sprintf('Canonicalization method "%s" is not supported', $signature->canonicalizationMethod), Indication::Indeterminate, SubIndication::PolicyProcessingError);
        }

        $algorithm = SignatureAlgorithm::tryFromXmlUri($signature->signatureMethod);
        if ($algorithm === null) {
            $findings[] = Finding::error(FindingCodes::WEAK_SIGNATURE_ALGORITHM, \sprintf('Signature algorithm "%s" is not supported or no longer acceptable', $signature->signatureMethod), Indication::TotalFailed, SubIndication::CryptoConstraintsFailure);
        } elseif (!$this->policy->allowsSignature($algorithm)) {
            $findings[] = Finding::error(FindingCodes::WEAK_SIGNATURE_ALGORITHM, \sprintf('Signature algorithm %s is not allowed by the policy', $algorithm->value), Indication::TotalFailed, SubIndication::CryptoConstraintsFailure);
        }

        foreach ($signature->references as $reference) {
            $digest = HashAlgorithm::tryFromXmlUri($reference['digestMethod']);
            if ($digest === null || !$this->policy->allowsDigest($digest)) {
                $findings[] = Finding::error(FindingCodes::WEAK_DIGEST_ALGORITHM, \sprintf('Reference "%s" uses digest algorithm "%s", which is not allowed', $reference['uri'], $reference['digestMethod']), Indication::TotalFailed, SubIndication::CryptoConstraintsFailure);
            }
        }

        if ($signer !== null) {
            try {
                if ($signer->keyType() === \Allkiri\Crypto\KeyType::RSA && $signer->keyBits() < $this->policy->minimumRsaKeyBits) {
                    $findings[] = Finding::error(FindingCodes::WEAK_KEY, \sprintf('The signer\'s RSA key is %d bits; the policy requires at least %d', $signer->keyBits(), $this->policy->minimumRsaKeyBits), Indication::TotalFailed, SubIndication::CryptoConstraintsFailure);
                }
            } catch (\Allkiri\Crypto\CryptoException $e) {
                // A key type allkiri does not support, or a key it cannot read at all.
                $findings[] = Finding::error(FindingCodes::WEAK_KEY, $e->getMessage(), Indication::Indeterminate, SubIndication::CryptoConstraintsFailure);
            }
        }
    }

    /**
     * @param list<Finding> $findings
     */
    private function checkSigningCertificateReference(XadesSignature $signature, ?Certificate $signer, array &$findings): void
    {
        if ($signer === null) {
            $findings[] = Finding::error(FindingCodes::SIGNING_CERTIFICATE_MISSING, 'The signature carries no signing certificate', Indication::Indeterminate, SubIndication::NoSigningCertificateFound);

            return;
        }
        $references = $signature->signingCertificateReferences;
        if ($references === []) {
            $findings[] = Finding::error(FindingCodes::SIGNING_CERTIFICATE_REFERENCE_MISSING, 'The signed properties do not commit to a signing certificate', Indication::TotalFailed, SubIndication::FormatFailure);

            return;
        }
        $reference = $references[0];
        $digestAlgorithm = HashAlgorithm::tryFromXmlUri($reference['digestMethod']);
        if ($digestAlgorithm === null) {
            $findings[] = Finding::error(FindingCodes::WEAK_DIGEST_ALGORITHM, \sprintf('The signing certificate reference uses digest algorithm "%s"', $reference['digestMethod']), Indication::Indeterminate, SubIndication::CryptoConstraintsFailure);

            return;
        }
        if (!hash_equals($signer->fingerprint($digestAlgorithm), $reference['digest'])) {
            $findings[] = Finding::error(FindingCodes::SIGNING_CERTIFICATE_DIGEST_MISMATCH, 'The certificate in the signature is not the one the signer committed to', Indication::TotalFailed, SubIndication::SigConstraintsFailure);

            return;
        }
        $this->checkIssuerSerial($reference, $signer, $findings);
    }

    /**
     * A signature needs a certificate for signing. ETSI EN 319 412-2 requires
     * nonRepudiation (X.509's contentCommitment) in the key usage of a
     * certificate for electronic signatures; an authentication certificate from
     * the same CA does not have it. Like DSS and SiVa, this is a failed
     * certificate constraint rather than proof of forgery.
     *
     * @param list<Finding> $findings
     */
    private function checkSigningCertificateUsage(?Certificate $signer, array &$findings): void
    {
        if ($signer === null || \in_array('nonRepudiation', $signer->keyUsage(), true)) {
            return;
        }
        $findings[] = Finding::error(FindingCodes::SIGNING_CERTIFICATE_KEY_USAGE, 'The signing certificate is not a certificate for signing: its key usage lacks nonRepudiation', Indication::Indeterminate, SubIndication::ChainConstraintsFailure);
    }

    /**
     * @param array{digestMethod: string, digest: string, issuerSerialV2: ?string, issuerName: ?string, serialNumber: ?string} $reference
     * @param list<Finding>                                                                                                    $findings
     */
    private function checkIssuerSerial(array $reference, Certificate $signer, array &$findings): void
    {
        if ($reference['issuerSerialV2'] !== null) {
            // IssuerSerial ::= SEQUENCE { GeneralNames, CertificateSerialNumber }
            try {
                $root = Asn1::decodeRaw($reference['issuerSerialV2']);
                $issuerName = $root->child(0)->child(0)->child(0)->der();
                $serial = $root->child(1)->integer()->toString();
            } catch (Asn1Exception $e) {
                $findings[] = Finding::warning(FindingCodes::ISSUER_SERIAL_MISMATCH, 'IssuerSerialV2 could not be read: ' . $e->getMessage());

                return;
            }
            if ($issuerName !== $signer->issuerNameDer() || $serial !== $signer->serialNumber()) {
                $findings[] = Finding::warning(FindingCodes::ISSUER_SERIAL_MISMATCH, 'IssuerSerialV2 does not match the signing certificate\'s issuer and serial number');
            }

            return;
        }
        if ($reference['serialNumber'] !== null && trim($reference['serialNumber']) !== $signer->serialNumber()) {
            $findings[] = Finding::warning(FindingCodes::ISSUER_SERIAL_MISMATCH, 'IssuerSerial does not match the signing certificate\'s serial number');
        }
    }

    /**
     * @param list<Finding> $findings
     */
    private function checkReferences(AsicContainer $container, XadesSignature $signature, \DOMElement $element, ?Certificate $signer, array &$findings): void
    {
        $result = $this->dsigVerifier->verify($element, new ContainerReferenceResolver($container), $signer);

        $signed = [];
        foreach ($result->references as $reference) {
            if ($reference->isSameDocument()) {
                if ($reference->ambiguous) {
                    $findings[] = Finding::error(FindingCodes::DUPLICATE_ID, $reference->problem ?? \sprintf('More than one element carries the Id that reference "%s" names', $reference->uri), Indication::TotalFailed, SubIndication::FormatFailure);
                } elseif (!$reference->isValid()) {
                    $findings[] = Finding::error(FindingCodes::SIGNED_PROPERTIES_DIGEST_MISMATCH, $reference->problem ?? 'The signed properties have been altered since they were signed', Indication::TotalFailed, SubIndication::HashFailure);
                }
                continue;
            }
            $name = rawurldecode($reference->uri);
            $signed[$name] = true;
            if (!$reference->resolved) {
                $findings[] = Finding::error(FindingCodes::SIGNED_DATA_MISSING, \sprintf('The signature covers "%s", which the container does not contain', $name), Indication::Indeterminate, SubIndication::SignedDataNotFound);
                continue;
            }
            if (!$reference->digestMatches) {
                $findings[] = Finding::error(FindingCodes::DATA_FILE_DIGEST_MISMATCH, \sprintf('"%s" has changed since it was signed', $name), Indication::TotalFailed, SubIndication::HashFailure);
            }
        }

        foreach ($container->dataFiles as $file) {
            if (!isset($signed[$file->name])) {
                $findings[] = Finding::error(FindingCodes::UNSIGNED_DATA_FILE, \sprintf('"%s" is in the container but this signature does not cover it', $file->name), Indication::TotalFailed, SubIndication::FormatFailure);
            }
        }

        // A duplicated Id is reported above; anything else that stops the
        // reference reaching this signature's own signed properties means the
        // properties in the report are not the ones that were signed.
        $unbound = $signature->unboundSignedPropertiesReference;
        if ($unbound !== null && $result->reference($unbound)?->ambiguous !== true) {
            $findings[] = Finding::error(FindingCodes::SIGNED_PROPERTIES_REFERENCE_MISSING, \sprintf('Reference "%s" does not cover this signature\'s own signed properties', $unbound), Indication::TotalFailed, SubIndication::FormatFailure);
        }

        if ($signer !== null && !$result->signatureValid) {
            $problem = $result->problems === [] ? 'the signature value does not verify' : implode('; ', $result->problems);
            $findings[] = Finding::error(FindingCodes::SIGNATURE_INVALID, 'The signature does not verify: ' . $problem, Indication::TotalFailed, SubIndication::SigCryptoFailure);
        }

        $this->checkDataObjectFormats($container, $signature, $findings);
    }

    /**
     * @param list<Finding> $findings
     */
    private function checkDataObjectFormats(AsicContainer $container, XadesSignature $signature, array &$findings): void
    {
        foreach ($signature->dataReferences() as $reference) {
            $mimeType = $signature->mimeTypeForReference($reference['id']);
            if ($mimeType === null || $mimeType === '') {
                if ($this->policy->requireDataObjectFormat) {
                    $findings[] = Finding::error(FindingCodes::MISSING_DATA_OBJECT_FORMAT, \sprintf('No DataObjectFormat states the media type of "%s", which BDOC requires', rawurldecode($reference['uri'])), Indication::TotalFailed, SubIndication::FormatFailure);
                }
                continue;
            }
            $file = $container->dataFile(rawurldecode($reference['uri']));
            if ($file !== null && $file->mimeType !== $mimeType) {
                $findings[] = Finding::warning(FindingCodes::MIME_TYPE_MISMATCH, \sprintf('The signature says "%s" is %s, the manifest says %s', $file->name, $mimeType, $file->mimeType));
            }
        }
    }

    /**
     * @param list<Finding> $findings
     */
    private function checkTimestamps(XadesSignature $signature, TrustStore $store, array &$findings): ?TimestampToken
    {
        if ($signature->signatureTimestamps === []) {
            return null;
        }
        $signatureValue = Xml::element(Xml::xpath($signature->element), 'ds:SignatureValue', $signature->element);
        if ($signatureValue === null) {
            return null;
        }
        $constraints = $this->policy->algorithmConstraints();

        foreach ($signature->signatureTimestamps as $entry) {
            try {
                $token = TimestampToken::fromDer($entry['token']);
            } catch (Asn1Exception $e) {
                $findings[] = Finding::error(FindingCodes::TIMESTAMP_INVALID, 'The signature timestamp could not be read: ' . $e->getMessage(), Indication::Indeterminate, SubIndication::NoPoe);
                continue;
            }

            $method = $entry['canonicalizationMethod'] === '' ? Ns::C14N_EXC : $entry['canonicalizationMethod'];
            if (!Canonicalizer::supports($method)) {
                $findings[] = Finding::error(FindingCodes::TIMESTAMP_INVALID, \sprintf('The timestamp uses canonicalization method "%s", which is not supported', $method), Indication::Indeterminate, SubIndication::NoPoe);
                continue;
            }
            $imprintAlgorithm = HashAlgorithm::tryFromOid($token->tstInfo()->hashAlgorithmOid);
            if ($imprintAlgorithm === null) {
                $findings[] = Finding::error(FindingCodes::TIMESTAMP_INVALID, 'The timestamp uses an unsupported digest algorithm', Indication::Indeterminate, SubIndication::NoPoe);
                continue;
            }

            $canonical = $this->canonicalizer->canonicalize($signatureValue, $method);
            $tsaCandidates = array_map(static fn($anchor): Certificate => $anchor->certificate, $store->anchors(ServiceType::tsaTypes()));

            try {
                $verification = $this->timestampVerifier->verify($token, $imprintAlgorithm, $imprintAlgorithm->digest($canonical), null, array_values($tsaCandidates), $constraints);
            } catch (TimestampException $e) {
                $findings[] = $e->reason === \Allkiri\Crypto\Tsp\TimestampVerificationException::REASON_ALGORITHM_NOT_ACCEPTED
                    ? Finding::error(FindingCodes::TIMESTAMP_WEAK_ALGORITHM, 'The signature timestamp cannot be relied on: ' . $e->getMessage(), Indication::Indeterminate, SubIndication::CryptoConstraintsFailureNoPoe)
                    : Finding::error(FindingCodes::TIMESTAMP_INVALID, 'The signature timestamp does not verify: ' . $e->getMessage(), Indication::Indeterminate, SubIndication::NoPoe);
                continue;
            }

            try {
                (new ChainBuilder($store, $constraints))->build($verification->tsaCertificate, $token->signedData()->certificates(), $token->genTime(), ServiceType::tsaTypes());
            } catch (ChainBuildingException $e) {
                $findings[] = $e->reason === ChainBuildingException::REASON_ALGORITHM_NOT_ACCEPTED
                    ? Finding::error(FindingCodes::TIMESTAMP_WEAK_ALGORITHM, 'The timestamp authority\'s certificate cannot be relied on: ' . $e->getMessage(), Indication::Indeterminate, SubIndication::CryptoConstraintsFailureNoPoe)
                    : Finding::error(FindingCodes::TIMESTAMP_NOT_TRUSTED, 'The timestamp authority is not trusted: ' . $e->getMessage(), Indication::Indeterminate, SubIndication::NoPoe);
                continue;
            }

            return $token;
        }

        return null;
    }

    /**
     * @param list<Finding> $findings
     *
     * @return \Allkiri\Trust\CertificateChain|null
     */
    private function checkChain(XadesSignature $signature, Certificate $signer, \DateTimeImmutable $at, TrustStore $store, array &$findings): ?\Allkiri\Trust\CertificateChain
    {
        try {
            return (new ChainBuilder($store, $this->policy->algorithmConstraints()))->build($signer, $signature->certificateValues, $at, ServiceType::caTypes());
        } catch (ChainBuildingException $e) {
            $findings[] = match ($e->reason) {
                ChainBuildingException::REASON_NOT_VALID_AT_TIME => $this->validityFinding($signer, $at, $e),
                ChainBuildingException::REASON_SIGNATURE => Finding::error(FindingCodes::CHAIN_INVALID, $e->getMessage(), Indication::TotalFailed, SubIndication::CertificateChainGeneralFailure),
                // Genuine, but made with what no longer counts: nothing here is
                // forged, and nothing proves it was made while it still counted.
                ChainBuildingException::REASON_ALGORITHM_NOT_ACCEPTED => Finding::error(FindingCodes::CHAIN_WEAK_ALGORITHM, 'The signer\'s certificate chain cannot be relied on: ' . $e->getMessage(), Indication::Indeterminate, SubIndication::CryptoConstraintsFailureNoPoe),
                // A path through certificates the signature did not carry might still conform.
                ChainBuildingException::REASON_PATH_LENGTH, ChainBuildingException::REASON_CA_KEY_USAGE => Finding::error(FindingCodes::CHAIN_CONSTRAINT_VIOLATED, 'The signer\'s certificate chain breaks a CA\'s constraints: ' . $e->getMessage(), Indication::Indeterminate, SubIndication::ChainConstraintsFailure),
                default => Finding::error(FindingCodes::CHAIN_NOT_FOUND, 'The signer\'s certificate does not chain to a trusted CA: ' . $e->getMessage(), Indication::Indeterminate, SubIndication::NoCertificateChainFound),
            };

            return null;
        }
    }

    private function validityFinding(Certificate $signer, \DateTimeImmutable $at, ChainBuildingException $e): Finding
    {
        if ($at < $signer->notBefore()) {
            return Finding::error(FindingCodes::SIGNING_CERTIFICATE_NOT_YET_VALID, $e->getMessage(), Indication::TotalFailed, SubIndication::NotYetValid);
        }

        return Finding::error(FindingCodes::SIGNING_CERTIFICATE_EXPIRED, $e->getMessage(), Indication::Indeterminate, SubIndication::OutOfBoundsNotRevoked);
    }

    /**
     * @param list<Finding> $findings
     */
    private function checkRevocation(XadesSignature $signature, Certificate $signer, \Allkiri\Trust\CertificateChain $chain, \DateTimeImmutable $at, TrustStore $store, array &$findings): ?OcspVerificationResult
    {
        if ($signature->ocspValues === []) {
            $findings[] = Finding::error(FindingCodes::REVOCATION_MISSING, 'The signature carries no revocation data, so it cannot be shown that the certificate was valid when it was used', Indication::Indeterminate, SubIndication::TryLater);

            return null;
        }

        $issuer = $chain->issuerOfLeaf();
        $trustedResponders = array_map(static fn($anchor): Certificate => $anchor->certificate, $store->anchors(ServiceType::ocspTypes()));
        $options = (new OcspVerificationOptions(NonceMode::Ignore, [], $this->policy->clockSkewSeconds, null, $this->policy->algorithmConstraints()))->withTrustedResponders(array_values($trustedResponders));

        $verified = [];
        $lastProblem = null;
        $weakness = null;
        foreach ($signature->ocspValues as $der) {
            try {
                $response = OcspResponse::fromDer($der);
            } catch (Asn1Exception $e) {
                $lastProblem = $e->getMessage();
                continue;
            }
            $producedAt = $response->basic()?->producedAt() ?? $at;

            try {
                $verified[] = $this->ocspVerifier->verify($response, $signer, $issuer, null, $producedAt, $options);
            } catch (OcspException $e) {
                if ($e->reason === \Allkiri\Crypto\Ocsp\OcspVerificationException::REASON_ALGORITHM_NOT_ACCEPTED) {
                    $weakness = $e->getMessage();
                } else {
                    $lastProblem = $e->getMessage();
                }
            }
        }

        if ($verified === []) {
            // An answer that holds up in every other way but is signed with what no
            // longer counts is the more telling problem to report.
            if ($weakness !== null) {
                $findings[] = Finding::error(FindingCodes::REVOCATION_WEAK_ALGORITHM, 'The revocation answer cannot be relied on: ' . $weakness, Indication::Indeterminate, SubIndication::CryptoConstraintsFailureNoPoe);

                return null;
            }
            $findings[] = Finding::error(FindingCodes::REVOCATION_INVALID, 'No usable OCSP response' . ($lastProblem === null ? '' : ': ' . $lastProblem), Indication::Indeterminate, SubIndication::TryLater);

            return null;
        }

        $chosen = $this->preferredResponse($verified, $at);
        if ($chosen->status() === CertStatus::Revoked) {
            $findings[] = Finding::error(FindingCodes::CERTIFICATE_REVOKED, \sprintf('The signer\'s certificate was revoked%s', $chosen->single->revokedAt === null ? '' : ' on ' . $chosen->single->revokedAt->format(DATE_ATOM)), Indication::TotalFailed, SubIndication::Revoked);
        } elseif ($chosen->status() === CertStatus::Unknown) {
            $findings[] = Finding::error(FindingCodes::CERTIFICATE_STATUS_UNKNOWN, 'The responder does not know the signer\'s certificate', Indication::Indeterminate, SubIndication::TryLater);
        }

        return $chosen;
    }

    /**
     * Which of several verified answers speaks for the certificate.
     *
     * A revoked answer outweighs any other, in whatever order they come: a good
     * answer beside it says nothing about the revocation. Otherwise the newest
     * answer produced within the policy's window after the signature time
     * counts, so a later one that would fail the order check on its own
     * lateness does not displace a sound one. Only when none falls inside the
     * window does the newest overall count.
     *
     * @param non-empty-list<OcspVerificationResult> $verified
     */
    private function preferredResponse(array $verified, \DateTimeImmutable $signatureTime): OcspVerificationResult
    {
        $revoked = array_values(array_filter($verified, static fn(OcspVerificationResult $answer): bool => $answer->status() === CertStatus::Revoked));
        if ($revoked !== []) {
            return self::newest($revoked);
        }

        $from = $signatureTime->getTimestamp() - $this->policy->clockSkewSeconds;
        $until = $signatureTime->getTimestamp() + $this->policy->ocspDelayErrorSeconds;
        $inWindow = array_values(array_filter($verified, static fn(OcspVerificationResult $answer): bool => $answer->producedAt()->getTimestamp() >= $from && $answer->producedAt()->getTimestamp() <= $until));

        return self::newest($inWindow !== [] ? $inWindow : $verified);
    }

    /**
     * The answer produced last; the earliest in the document among equals.
     *
     * @param non-empty-list<OcspVerificationResult> $answers
     */
    private static function newest(array $answers): OcspVerificationResult
    {
        $newest = $answers[0];
        foreach ($answers as $answer) {
            if ($answer->producedAt() > $newest->producedAt()) {
                $newest = $answer;
            }
        }

        return $newest;
    }

    /**
     * Verify every archive timestamp: what it covers, its own signature, and
     * that its authority is trusted.
     *
     * An archive timestamp is what lets a signature outlast the algorithms it
     * was made with, so a broken one is worth reporting even when everything
     * beneath it is sound. The signature is still good today; the protection it
     * was given for tomorrow is not there.
     *
     * @param list<Finding> $findings
     *
     * @return \DateTimeImmutable|null the time of the last one that verified
     */
    private function checkArchiveTimestamps(
        AsicContainer $container,
        \DOMElement $element,
        TrustStore $store,
        ?TimestampToken $signatureTimestamp,
        array &$findings,
    ): ?\DateTimeImmutable {
        $archives = Xml::elements(Xml::xpath($element), './/xadesv141:ArchiveTimeStamp', $element);
        if ($archives === []) {
            return null;
        }

        $resolver = new ContainerReferenceResolver($container);
        $tsaCandidates = array_values(array_map(
            static fn(\Allkiri\Trust\TrustAnchor $anchor): Certificate => $anchor->certificate,
            $store->anchors(ServiceType::tsaTypes()),
        ));
        $latest = null;
        $previous = $signatureTimestamp?->genTime();
        $constraints = $this->policy->algorithmConstraints();

        foreach ($archives as $index => $archive) {
            $number = $index + 1;

            $encoded = Xml::base64(Xml::xpath($archive), './/xades:EncapsulatedTimeStamp', $archive);
            if ($encoded === null) {
                $findings[] = $this->archiveFinding($number, 'carries no token');
                continue;
            }

            try {
                $token = TimestampToken::fromDer($encoded);
            } catch (Asn1Exception $e) {
                $findings[] = $this->archiveFinding($number, 'could not be read: ' . $e->getMessage());
                continue;
            }

            $method = ArchiveTimestampData::canonicalizationOf($archive);
            if (!Canonicalizer::supports($method)) {
                $findings[] = $this->archiveFinding($number, \sprintf('uses canonicalization method "%s", which is not supported', $method));
                continue;
            }
            $imprintAlgorithm = HashAlgorithm::tryFromOid($token->tstInfo()->hashAlgorithmOid);
            if ($imprintAlgorithm === null) {
                $findings[] = $this->archiveFinding($number, 'uses an unsupported digest algorithm');
                continue;
            }

            try {
                $covered = $this->archiveTimestampData->forExistingTimestamp($element, $archive, $resolver);
            } catch (XadesException $e) {
                $findings[] = $this->archiveFinding($number, 'covers something that cannot be reconstructed: ' . $e->getMessage());
                continue;
            }

            try {
                $verification = $this->timestampVerifier->verify($token, $imprintAlgorithm, $imprintAlgorithm->digest($covered), null, $tsaCandidates, $constraints);
            } catch (TimestampException $e) {
                $findings[] = $e->reason === \Allkiri\Crypto\Tsp\TimestampVerificationException::REASON_ALGORITHM_NOT_ACCEPTED
                    ? $this->archiveWeakFinding($number, $e->getMessage())
                    : $this->archiveFinding($number, 'does not verify: ' . $e->getMessage());
                continue;
            }

            try {
                (new ChainBuilder($store, $constraints))->build($verification->tsaCertificate, $token->signedData()->certificates(), $token->genTime(), ServiceType::tsaTypes());
            } catch (ChainBuildingException $e) {
                if ($e->reason === ChainBuildingException::REASON_ALGORITHM_NOT_ACCEPTED) {
                    $findings[] = $this->archiveWeakFinding($number, $e->getMessage());
                    continue;
                }
                $findings[] = Finding::error(
                    FindingCodes::ARCHIVE_TIMESTAMP_NOT_TRUSTED,
                    \sprintf('The authority behind archive timestamp %d is not trusted: %s', $number, $e->getMessage()),
                    Indication::Indeterminate,
                    SubIndication::NoPoe,
                );
                continue;
            }

            // Each archive timestamp covers the ones before it, so its own time
            // has to come after theirs, or the chain of proof runs backwards.
            if ($previous !== null && $token->genTime() < $previous) {
                $findings[] = Finding::error(
                    FindingCodes::ARCHIVE_TIMESTAMP_ORDER,
                    \sprintf('Archive timestamp %d is dated before what it covers', $number),
                    Indication::TotalFailed,
                    SubIndication::TimestampOrderFailure,
                );
                continue;
            }

            $previous = $token->genTime();
            $latest = $token->genTime();
        }

        return $latest;
    }

    private function archiveWeakFinding(int $number, string $problem): Finding
    {
        return Finding::error(
            FindingCodes::ARCHIVE_TIMESTAMP_WEAK_ALGORITHM,
            \sprintf('Archive timestamp %d cannot be relied on: %s', $number, $problem),
            Indication::Indeterminate,
            SubIndication::CryptoConstraintsFailureNoPoe,
        );
    }

    private function archiveFinding(int $number, string $problem): Finding
    {
        return Finding::error(
            FindingCodes::ARCHIVE_TIMESTAMP_INVALID,
            \sprintf('Archive timestamp %d %s', $number, $problem),
            Indication::Indeterminate,
            SubIndication::NoPoe,
        );
    }

    /**
     * @param list<Finding> $findings
     */
    private function checkTimestampOcspOrder(TimestampToken $timestamp, OcspVerificationResult $ocsp, array &$findings): void
    {
        $delay = $ocsp->producedAt()->getTimestamp() - $timestamp->genTime()->getTimestamp();
        if ($delay < -$this->policy->clockSkewSeconds) {
            $findings[] = Finding::error(FindingCodes::OCSP_BEFORE_TIMESTAMP, \sprintf('The revocation answer is %d seconds older than the timestamp, so it does not prove the certificate was valid when the signature was made', -$delay), Indication::TotalFailed, SubIndication::TimestampOrderFailure);

            return;
        }
        if ($delay > $this->policy->ocspDelayErrorSeconds) {
            $findings[] = Finding::error(FindingCodes::OCSP_TIMESTAMP_DELTA_TOO_LARGE, \sprintf('The revocation answer was produced %d seconds after the timestamp, beyond the %d the policy allows', $delay, $this->policy->ocspDelayErrorSeconds), Indication::TotalFailed, SubIndication::TimestampOrderFailure);

            return;
        }
        if ($delay > $this->policy->ocspDelayWarningSeconds) {
            $findings[] = Finding::warning(FindingCodes::OCSP_TIMESTAMP_DELTA_WARNING, \sprintf('The revocation answer was produced %d seconds after the timestamp', $delay));
        }
    }

    /**
     * @return list<SignatureScope>
     */
    private function scopes(AsicContainer $container, XadesSignature $signature): array
    {
        $scopes = [];
        foreach ($signature->dataReferences() as $reference) {
            $name = rawurldecode($reference['uri']);
            $file = $container->dataFile($name);
            $mimeType = $file !== null ? $file->mimeType : $signature->mimeTypeForReference($reference['id']);
            $scopes[] = new SignatureScope($name, $mimeType ?? MimeTypes::DEFAULT);
        }

        return $scopes;
    }

    /**
     * @param list<Finding> $findings
     *
     * @return array{Indication, SubIndication|null}
     */
    private function verdict(array $findings): array
    {
        $indication = Indication::TotalPassed;
        $subIndication = null;
        foreach ($findings as $finding) {
            if ($finding->indication === null) {
                continue;
            }
            $worse = $indication->worse($finding->indication);
            if ($worse !== $indication || $subIndication === null) {
                $indication = $worse;
                $subIndication = $finding->subIndication;
            }
        }

        return [$indication, $indication === Indication::TotalPassed ? null : $subIndication];
    }
}
