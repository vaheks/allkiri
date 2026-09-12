<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Crypto\Certificate;
use Allkiri\Crypto\CertificateException;
use Allkiri\Crypto\HashAlgorithm;

/**
 * Reads a session status, refusing anything it cannot make sense of.
 *
 * Kept apart from the client so the rules are visible and testable on their
 * own: every field a successful session must carry is required here, because
 * later checks are only as good as the values they run on.
 */
final class SmartIdSessionStatusParser
{
    private function __construct() {}

    /**
     * @param array<string, mixed> $body
     */
    public static function parse(array $body): SmartIdSessionStatus
    {
        $state = $body['state'] ?? null;
        if (!\is_string($state) || $state === '') {
            throw self::malformed('the session status has no state');
        }
        if ($state !== SmartIdSessionStatus::STATE_COMPLETE) {
            return new SmartIdSessionStatus(SmartIdSessionStatus::STATE_RUNNING);
        }

        $result = $body['result'] ?? null;
        if (!\is_array($result)) {
            throw self::malformed('a complete session has no result');
        }
        /** @var array<string, mixed> $result */
        $rawEndResult = $result['endResult'] ?? null;
        if (!\is_string($rawEndResult) || $rawEndResult === '') {
            throw self::malformed('a complete session has no end result');
        }
        $endResult = SmartIdEndResult::tryFrom($rawEndResult);
        if ($endResult === null) {
            throw self::malformed(\sprintf('the session reported an unknown end result "%s"', $rawEndResult));
        }

        if ($endResult !== SmartIdEndResult::Ok) {
            return new SmartIdSessionStatus(
                SmartIdSessionStatus::STATE_COMPLETE,
                $endResult,
                refusedInteraction: self::refusedInteraction($result),
            );
        }

        $signature = $body['signature'] ?? null;
        if (!\is_array($signature)) {
            throw self::malformed('the session succeeded but carries no signature');
        }
        /** @var array<string, mixed> $signature */
        $certificate = $body['cert'] ?? null;
        if (!\is_array($certificate)) {
            throw self::malformed('the session succeeded but carries no certificate');
        }
        /** @var array<string, mixed> $certificate */

        return new SmartIdSessionStatus(
            SmartIdSessionStatus::STATE_COMPLETE,
            $endResult,
            self::documentNumber($result),
            self::signatureValue($signature),
            self::requiredString($signature, 'signature.signatureAlgorithm'),
            self::pssParameters($signature),
            self::certificate($certificate),
            self::certificateLevel($certificate),
            self::optionalString($signature, 'serverRandom'),
            self::optionalString($signature, 'userChallenge'),
            self::flowType($signature),
            self::interactionTypeUsed($body),
            null,
            self::optionalString($body, 'deviceIpAddress'),
            self::requiredString($body, 'signatureProtocol'),
        );
    }

    /**
     * @param array<string, mixed> $result
     */
    private static function refusedInteraction(array $result): ?InteractionType
    {
        $details = $result['details'] ?? null;
        if (!\is_array($details)) {
            return null;
        }
        $interaction = $details['interaction'] ?? null;

        // The service also uses short forms such as "verificationCodeChoice"
        // that are not request interaction types; those simply go unnamed.
        return \is_string($interaction) ? InteractionType::tryFrom($interaction) : null;
    }

    /**
     * @param array<string, mixed> $result
     */
    private static function documentNumber(array $result): DocumentNumber
    {
        $value = $result['documentNumber'] ?? null;
        if (!\is_string($value) || $value === '') {
            throw self::malformed('the session succeeded without naming the account that answered');
        }

        try {
            return new DocumentNumber($value);
        } catch (\Allkiri\Exception\InvalidArgumentException $exception) {
            throw self::malformed(\sprintf('the session reported an unusable document number "%s"', $value), $exception);
        }
    }

    /**
     * @param array<string, mixed> $signature
     */
    private static function signatureValue(array $signature): string
    {
        $value = base64_decode(self::requiredString($signature, 'signature.value', $signature['value'] ?? null), true);
        if ($value === false || $value === '') {
            throw self::malformed('the signature value is not base64');
        }

        return $value;
    }

    /**
     * PSS parameters, or null when the legacy PKCS#1 v1.5 algorithm was used.
     *
     * @param array<string, mixed> $signature
     */
    private static function pssParameters(array $signature): ?RsaPssParameters
    {
        $algorithm = self::requiredString($signature, 'signature.signatureAlgorithm');
        if ($algorithm !== SmartIdClient::SIGNATURE_ALGORITHM_PSS) {
            return null;
        }

        $parameters = $signature['signatureAlgorithmParameters'] ?? null;
        if (!\is_array($parameters)) {
            throw self::malformed('a PSS signature arrived without its parameters');
        }
        /** @var array<string, mixed> $parameters */
        $hash = self::hashAlgorithm(self::requiredString($parameters, 'signatureAlgorithmParameters.hashAlgorithm'));

        $maskGen = $parameters['maskGenAlgorithm'] ?? null;
        if (!\is_array($maskGen)) {
            throw self::malformed('a PSS signature arrived without a mask generation algorithm');
        }
        /** @var array<string, mixed> $maskGen */
        $maskGenName = self::requiredString($maskGen, 'maskGenAlgorithm.algorithm');
        if (strtolower($maskGenName) !== 'id-mgf1' && strtolower($maskGenName) !== 'mgf1') {
            throw self::malformed(\sprintf('the mask generation algorithm is "%s", and only MGF1 is usable here', $maskGenName));
        }
        $maskParameters = $maskGen['parameters'] ?? null;
        if (!\is_array($maskParameters)) {
            throw self::malformed('the mask generation algorithm arrived without parameters');
        }
        /** @var array<string, mixed> $maskParameters */
        $maskHash = self::hashAlgorithm(self::requiredString($maskParameters, 'maskGenAlgorithm.parameters.hashAlgorithm'));

        $saltLength = $parameters['saltLength'] ?? null;
        if (!\is_int($saltLength)) {
            throw self::malformed('the PSS salt length is missing or not a number');
        }

        return new RsaPssParameters(
            $hash,
            $maskHash,
            $saltLength,
            self::requiredString($parameters, 'signatureAlgorithmParameters.trailerField'),
        );
    }

    private static function hashAlgorithm(string $name): HashAlgorithm
    {
        // Smart-ID spells them "SHA-256"; SHA-3 is accepted by the API but has
        // no XML-DSig signature method in the profile we produce.
        return match (strtoupper($name)) {
            'SHA-256', 'SHA256' => HashAlgorithm::SHA256,
            'SHA-384', 'SHA384' => HashAlgorithm::SHA384,
            'SHA-512', 'SHA512' => HashAlgorithm::SHA512,
            default => throw self::malformed(\sprintf('the hash algorithm "%s" cannot be used in a XAdES signature', $name)),
        };
    }

    /**
     * @param array<string, mixed> $certificate
     */
    private static function certificate(array $certificate): Certificate
    {
        try {
            return Certificate::fromBase64(self::requiredString($certificate, 'cert.value'));
        } catch (CertificateException $exception) {
            throw self::malformed('the certificate cannot be read: ' . $exception->getMessage(), $exception);
        }
    }

    /**
     * @param array<string, mixed> $certificate
     */
    private static function certificateLevel(array $certificate): CertificateLevel
    {
        $raw = self::requiredString($certificate, 'cert.certificateLevel');

        return CertificateLevel::tryFrom($raw)
            ?? throw self::malformed(\sprintf('the certificate level "%s" is unknown', $raw));
    }

    /**
     * @param array<string, mixed> $signature
     */
    private static function flowType(array $signature): ?FlowType
    {
        $raw = $signature['flowType'] ?? null;
        if (!\is_string($raw) || $raw === '') {
            return null;
        }

        return FlowType::tryFrom($raw)
            ?? throw self::malformed(\sprintf('the flow type "%s" is unknown', $raw));
    }

    /**
     * @param array<string, mixed> $body
     */
    private static function interactionTypeUsed(array $body): InteractionType
    {
        $raw = $body['interactionTypeUsed'] ?? null;
        if (!\is_string($raw) || $raw === '') {
            throw self::malformed('the session succeeded without saying which dialogue the app showed');
        }

        return InteractionType::tryFrom($raw)
            ?? throw self::malformed(\sprintf('the app reported an unknown dialogue "%s"', $raw));
    }

    /**
     * @param array<string, mixed> $body
     */
    private static function requiredString(array $body, string $name, mixed $value = null): string
    {
        $value ??= $body[self::leaf($name)] ?? null;
        if (!\is_string($value) || $value === '') {
            throw self::malformed(\sprintf('the session status is missing "%s"', $name));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $body
     */
    private static function optionalString(array $body, string $key): ?string
    {
        $value = $body[$key] ?? null;

        return \is_string($value) && $value !== '' ? $value : null;
    }

    private static function leaf(string $name): string
    {
        $parts = explode('.', $name);

        return $parts[\count($parts) - 1];
    }

    private static function malformed(string $what, ?\Throwable $previous = null): SmartIdApiException
    {
        return new SmartIdApiException(
            SmartIdApiException::REASON_MALFORMED_RESPONSE,
            'Smart-ID answered with something unusable: ' . $what,
            null,
            $previous,
        );
    }
}
