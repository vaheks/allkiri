<?php

declare(strict_types=1);

namespace Allkiri\Xades\Model;

use Allkiri\Crypto\Certificate;
use Allkiri\Xades\Ns;

/**
 * Read model of one XAdES signature as found in a container: everything the
 * validator needs, parsed tolerantly (missing parts are null or empty, and
 * oddities land in `warnings`).
 */
final readonly class XadesSignature
{
    /**
     * @param list<array{id: string, uri: string, type: string, digestMethod: string, digestValue: string, transforms: list<string>}> $references
     * @param list<Certificate>                                                                                                        $keyInfoCertificates
     * @param list<array{digestMethod: string, digest: string, issuerSerialV2: ?string, issuerName: ?string, serialNumber: ?string}> $signingCertificateReferences
     * @param list<array{objectReference: string, mimeType: string}>                                                                  $dataObjectFormats
     * @param list<array{id: string, canonicalizationMethod: string, token: string}>                                                  $signatureTimestamps
     * @param list<Certificate>                                                                                                        $certificateValues
     * @param list<string>                                                                                                             $ocspValues DER OCSPResponses
     * @param list<string>                                                                                                             $claimedRoles
     * @param list<string>                                                                                                             $warnings
     */
    public function __construct(
        public \DOMElement $element,
        public string $id,
        public string $signatureMethod,
        public string $canonicalizationMethod,
        public array $references,
        public ?string $signatureValue,
        public array $keyInfoCertificates,
        public ?\DateTimeImmutable $signingTime,
        public bool $signingCertificateIsV2,
        public array $signingCertificateReferences,
        public array $dataObjectFormats,
        public bool $hasSignaturePolicyIdentifier,
        public array $signatureTimestamps,
        public array $certificateValues,
        public array $ocspValues,
        public int $crlValueCount,
        public int $archiveTimestampCount,
        public array $claimedRoles,
        public ?string $productionPlace,
        public array $warnings,
        /**
         * The URI of a signed-properties reference that does not resolve to
         * this signature's own SignedProperties. Their contents are then left
         * unread, because they are not what was signed.
         */
        public ?string $unboundSignedPropertiesReference = null,
    ) {}

    public function signerCertificate(): ?Certificate
    {
        return $this->keyInfoCertificates[0] ?? null;
    }

    /**
     * @return list<array{id: string, uri: string, type: string, digestMethod: string, digestValue: string, transforms: list<string>}>
     */
    public function dataReferences(): array
    {
        return array_values(array_filter($this->references, static fn(array $r): bool => $r['uri'] !== '' && !str_starts_with($r['uri'], '#')));
    }

    /**
     * @return array{id: string, uri: string, type: string, digestMethod: string, digestValue: string, transforms: list<string>}|null
     */
    public function signedPropertiesReference(): ?array
    {
        foreach ($this->references as $reference) {
            if (\in_array($reference['type'], [Ns::TYPE_SIGNED_PROPERTIES, Ns::TYPE_SIGNED_PROPERTIES_V111], true)) {
                return $reference;
            }
        }

        return null;
    }

    public function mimeTypeForReference(string $referenceId): ?string
    {
        foreach ($this->dataObjectFormats as $format) {
            if ($format['objectReference'] === '#' . $referenceId) {
                return $format['mimeType'];
            }
        }

        return null;
    }
}
