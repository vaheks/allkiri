<?php

declare(strict_types=1);

namespace Allkiri\Container;

use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Exception\InvalidArgumentException;

/**
 * One signed file inside a container.
 */
final readonly class DataFile
{
    public function __construct(
        public string $name,
        public string $content,
        public string $mimeType = 'application/octet-stream',
    ) {
        if ($name === '' || str_contains($name, "\0")) {
            throw new InvalidArgumentException('Data file name must not be empty or contain a null byte');
        }
        if (str_starts_with($name, 'META-INF/') || $name === 'mimetype') {
            throw new InvalidArgumentException(\sprintf('"%s" is reserved by the ASiC-E format', $name));
        }
        if (self::unsafeNameProblem($name) !== null) {
            throw new InvalidArgumentException(\sprintf('Data file name "%s" must be a relative path without traversal', $name));
        }
    }

    /**
     * What would make an unzip tool place an entry of this name outside the
     * folder it extracts to, or make it a name no file system holds; null when
     * nothing does.
     *
     * @internal
     */
    public static function unsafeNameProblem(string $name): ?string
    {
        return match (true) {
            $name === '' => 'is empty',
            str_contains($name, "\0") => 'contains a null byte',
            str_contains($name, '\\') => 'contains a backslash, which Windows reads as a directory separator',
            str_starts_with($name, '/') => 'is an absolute path',
            preg_match('#(^|/)\.\.(/|$)#', $name) === 1 => 'climbs out of its folder with ".."',
            default => null,
        };
    }

    public static function fromString(string $name, string $content, ?string $mimeType = null): self
    {
        return new self($name, $content, $mimeType ?? MimeTypes::guess($name));
    }

    /**
     * @param string|null $name the name to store it under; the file's own basename by default
     */
    public static function fromPath(string $path, ?string $name = null, ?string $mimeType = null): self
    {
        $content = @file_get_contents($path);
        if ($content === false) {
            throw new ContainerException(\sprintf('Could not read "%s"', $path));
        }
        $name ??= basename($path);

        return self::fromString($name, $content, $mimeType);
    }

    public function digest(HashAlgorithm $algorithm = HashAlgorithm::SHA256): string
    {
        return $algorithm->digest($this->content);
    }

    public function size(): int
    {
        return \strlen($this->content);
    }
}
