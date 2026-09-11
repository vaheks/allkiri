<?php

declare(strict_types=1);

namespace Allkiri\Container;

use Allkiri\Container\Zip\ZipEntry;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Exception\InvalidArgumentException;

/**
 * An ASiC-E container: data files, signature files and the manifest.
 *
 * Immutable. Adding a signature returns a new container that still carries
 * the original ZIP entries, so writing it back preserves every signed byte.
 */
final readonly class AsicContainer
{
    /**
     * @param list<DataFile>           $dataFiles
     * @param list<SignatureFile>      $signatureFiles
     * @param list<ZipEntry>           $originalEntries the entries as read, empty for a new container
     * @param list<StructuralFinding>  $structuralFindings
     */
    private function __construct(
        public array $dataFiles,
        public array $signatureFiles,
        public Manifest $manifest,
        public array $originalEntries = [],
        public array $structuralFindings = [],
    ) {}

    /**
     * A new container holding these files and nothing else.
     */
    public static function create(DataFile ...$dataFiles): self
    {
        $files = array_values($dataFiles);
        if ($files === []) {
            throw new InvalidArgumentException('A container needs at least one data file');
        }
        $names = [];
        foreach ($files as $file) {
            if (isset($names[$file->name])) {
                throw new InvalidArgumentException(\sprintf('Duplicate data file name "%s"', $file->name));
            }
            $names[$file->name] = true;
        }

        return new self($files, [], Manifest::forDataFiles($files));
    }

    /**
     * @param list<DataFile>          $dataFiles
     * @param list<SignatureFile>     $signatureFiles
     * @param list<ZipEntry>          $originalEntries
     * @param list<StructuralFinding> $findings
     *
     * @internal used by {@see AsicReader}
     */
    public static function fromParts(array $dataFiles, array $signatureFiles, Manifest $manifest, array $originalEntries, array $findings): self
    {
        return new self($dataFiles, $signatureFiles, $manifest, $originalEntries, $findings);
    }

    public function withSignatureFile(SignatureFile $file): self
    {
        foreach ($this->signatureFiles as $existing) {
            if ($existing->name === $file->name) {
                throw new InvalidArgumentException(\sprintf('The container already has a "%s"', $file->name));
            }
        }

        return new self($this->dataFiles, [...$this->signatureFiles, $file], $this->manifest, $this->originalEntries, $this->structuralFindings);
    }

    /**
     * The name the next signature file should take.
     */
    public function nextSignatureFileName(): string
    {
        $next = 0;
        foreach ($this->signatureFiles as $file) {
            $index = $file->index();
            if ($index !== null && $index >= $next) {
                $next = $index + 1;
            }
        }

        return \sprintf('META-INF/signatures%d.xml', $next);
    }

    public function dataFile(string $name): ?DataFile
    {
        foreach ($this->dataFiles as $file) {
            if ($file->name === $name) {
                return $file;
            }
        }

        return null;
    }

    public function signatureFile(string $name): ?SignatureFile
    {
        foreach ($this->signatureFiles as $file) {
            if ($file->name === $name) {
                return $file;
            }
        }

        return null;
    }

    /**
     * Identifies the exact set of data files being signed, so a signing
     * session started against one container cannot be finished against another.
     */
    public function fingerprint(): string
    {
        $parts = [];
        foreach ($this->dataFiles as $file) {
            $parts[] = $file->name . "\0" . $file->mimeType . "\0" . bin2hex($file->digest());
        }
        sort($parts);

        return bin2hex(HashAlgorithm::SHA256->digest(implode("\n", $parts)));
    }

    public function isNew(): bool
    {
        return $this->originalEntries === [];
    }

    /**
     * @return list<StructuralFinding> the fatal ones only
     */
    public function fatalFindings(): array
    {
        return array_values(array_filter($this->structuralFindings, static fn(StructuralFinding $f): bool => $f->fatal));
    }
}
