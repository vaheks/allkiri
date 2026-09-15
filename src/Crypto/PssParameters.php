<?php

declare(strict_types=1);

namespace Allkiri\Crypto;

use Allkiri\Crypto\Asn1\Asn1;
use Allkiri\Crypto\Asn1\Asn1Exception;
use Allkiri\Crypto\Asn1\Node;
use Allkiri\Crypto\Asn1\Oids;
use phpseclib3\File\ASN1 as PhpseclibAsn1;

/**
 * The RSASSA-PSS parameters of a signature on a certificate, an OCSP response
 * or a CMS signer (RFC 4055 §3.1).
 *
 * Only one profile is accepted, the one RFC 4055 recommends and certificate
 * authorities issue: SHA-256, SHA-384 or SHA-512, MGF1 with the same hash, a
 * salt as long as the digest, and the standard trailer.
 *
 * The fields are read one by one rather than through a map that fills in
 * defaults. An absent field means SHA-1, or a 20-byte salt, and that has to be
 * refused rather than quietly read as something else.
 */
final readonly class PssParameters
{
    private function __construct(
        public HashAlgorithm $hash,
        public int $saltLength,
    ) {}

    /**
     * @param string $der the RSASSA-PSS-params SEQUENCE
     *
     * @throws UnsupportedAlgorithmException for anything outside the profile, saying what
     */
    public static function fromDer(string $der): self
    {
        try {
            $sequence = Asn1::decodeRaw($der);
            if (!$sequence->isSequence()) {
                throw new Asn1Exception('not a SEQUENCE');
            }
            $fields = [];
            $lastTag = -1;
            foreach ($sequence->children() as $field) {
                $tag = $field->isTagged() ? $field->tag() : -1;
                if ($tag <= $lastTag || $tag > 3) {
                    throw new Asn1Exception('its fields are not [0] to [3], in order and once each');
                }
                $fields[$tag] = $field->child(0);
                $lastTag = $tag;
            }

            $hash = isset($fields[0])
                ? self::hash($fields[0], 'hash')
                : throw new UnsupportedAlgorithmException('RSASSA-PSS parameters that name no hash mean SHA-1, which is not accepted');

            $mask = $fields[1] ?? throw new UnsupportedAlgorithmException('RSASSA-PSS parameters that name no mask generation function mean MGF1 with SHA-1, which is not accepted');
            if (!$mask->isSequence() || $mask->childCount() !== 2 || $mask->child(0)->oid() !== Oids::MGF1) {
                throw new UnsupportedAlgorithmException('RSASSA-PSS with a mask generation function other than MGF1 is not accepted');
            }
            $maskHash = self::hash($mask->child(1), 'mask generation hash');
            if ($maskHash !== $hash) {
                throw new UnsupportedAlgorithmException(\sprintf('RSASSA-PSS whose mask generation function uses %s while the digest uses %s is not accepted', $maskHash->name(true), $hash->name(true)));
            }

            $saltLength = isset($fields[2]) ? self::int($fields[2]) : 20;
            if ($saltLength !== $hash->digestLength()) {
                throw new UnsupportedAlgorithmException(\sprintf('RSASSA-PSS with a %d-byte salt is not accepted; with %s the salt is %d bytes', $saltLength, $hash->name(true), $hash->digestLength()));
            }
            if (isset($fields[3]) && self::int($fields[3]) !== 1) {
                throw new UnsupportedAlgorithmException('RSASSA-PSS with a trailer field other than 1 is not accepted');
            }

            return new self($hash, $saltLength);
        } catch (Asn1Exception $e) {
            throw new UnsupportedAlgorithmException('Malformed RSASSA-PSS parameters: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * A hash AlgorithmIdentifier, whose parameters RFC 4055 §2.1 allows to be NULL or absent.
     */
    private static function hash(Node $identifier, string $what): HashAlgorithm
    {
        if (!$identifier->isSequence() || $identifier->childCount() < 1 || $identifier->childCount() > 2) {
            throw new Asn1Exception(\sprintf('the %s is not an AlgorithmIdentifier', $what));
        }
        if ($identifier->childCount() === 2 && ($identifier->child(1)->isTagged() || $identifier->child(1)->type() !== PhpseclibAsn1::TYPE_NULL)) {
            throw new UnsupportedAlgorithmException(\sprintf('RSASSA-PSS whose %s carries parameters is not accepted', $what));
        }
        $oid = $identifier->child(0)->oid();

        return HashAlgorithm::tryFromOid($oid)
            ?? throw new UnsupportedAlgorithmException(\sprintf('RSASSA-PSS with %s as its %s is not accepted', $oid === Oids::SHA1 ? 'SHA-1' : $oid, $what));
    }

    private static function int(Node $node): int
    {
        $int = filter_var($node->integer()->toString(), FILTER_VALIDATE_INT);
        if ($int === false) {
            throw new Asn1Exception('an integer out of range');
        }

        return $int;
    }
}
