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
use Allkiri\Crypto\UnsupportedAlgorithmException;
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
use Allkiri\Xades\Model\XadesSignature;
use Allkiri\Xades\Model\XadesSignatureParser;
use Allkiri\Xades\Ns;

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
            $findings[] = Finding::warning(FindingCodes::LTA_NOT_VERIFIED, 'The archive timestamp is reported but not verified; allkiri validates up to LT');

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
            } catch (UnsupportedAlgorithmException $e) {
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
                if (!$reference->isValid()) {
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
                $verification = $this->timestampVerifier->verify($token, $imprintAlgorithm, $imprintAlgorithm->digest($canonical), null, array_values($tsaCandidates));
            } catch (TimestampException $e) {
                $findings[] = Finding::error(FindingCodes::TIMESTAMP_INVALID, 'The signature timestamp does not verify: ' . $e->getMessage(), Indication::Indeterminate, SubIndication::NoPoe);
                continue;
            }

            try {
                (new ChainBuilder($store))->build($verification->tsaCertificate, $token->signedData()->certificates(), $token->genTime(), ServiceType::tsaTypes());
            } catch (ChainBuildingException $e) {
                $findings[] = Finding::error(FindingCodes::TIMESTAMP_NOT_TRUSTED, 'The timestamp authority is not trusted: ' . $e->getMessage(), Indication::Indeterminate, SubIndication::NoPoe);
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
            return (new ChainBuilder($store))->build($signer, $signature->certificateValues, $at, ServiceType::caTypes());
        } catch (ChainBuildingException $e) {
            $findings[] = match ($e->reason) {
                ChainBuildingException::REASON_NOT_VALID_AT_TIME => $this->validityFinding($signer, $at, $e),
                ChainBuildingException::REASON_SIGNATURE => Finding::error(FindingCodes::CHAIN_INVALID, $e->getMessage(), Indication::TotalFailed, SubIndication::CertificateChainGeneralFailure),
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
        $options = (new OcspVerificationOptions(NonceMode::Ignore, [], $this->policy->clockSkewSeconds, null))->withTrustedResponders(array_values($trustedResponders));

        $lastProblem = null;
        foreach ($signature->ocspValues as $der) {
            try {
                $response = OcspResponse::fromDer($der);
            } catch (Asn1Exception $e) {
                $lastProblem = $e->getMessage();
                continue;
            }
            $producedAt = $response->basic()?->producedAt() ?? $at;

            try {
                $verification = $this->ocspVerifier->verify($response, $signer, $issuer, null, $producedAt, $options);
            } catch (OcspException $e) {
                $lastProblem = $e->getMessage();
                continue;
            }

            switch ($verification->status()) {
                case CertStatus::Good:
                    return $verification;
                case CertStatus::Revoked:
                    $findings[] = Finding::error(FindingCodes::CERTIFICATE_REVOKED, \sprintf('The signer\'s certificate was revoked%s', $verification->single->revokedAt === null ? '' : ' on ' . $verification->single->revokedAt->format(DATE_ATOM)), Indication::TotalFailed, SubIndication::Revoked);

                    return $verification;
                case CertStatus::Unknown:
                    $findings[] = Finding::error(FindingCodes::CERTIFICATE_STATUS_UNKNOWN, 'The responder does not know the signer\'s certificate', Indication::Indeterminate, SubIndication::TryLater);

                    return $verification;
            }
        }

        $findings[] = Finding::error(FindingCodes::REVOCATION_INVALID, 'No usable OCSP response' . ($lastProblem === null ? '' : ': ' . $lastProblem), Indication::Indeterminate, SubIndication::TryLater);

        return null;
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
