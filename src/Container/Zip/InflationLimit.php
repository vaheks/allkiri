<?php

declare(strict_types=1);

namespace Allkiri\Container\Zip;

use Allkiri\Exception\InvalidArgumentException;

/**
 * How much a container is allowed to expand when it is read.
 *
 * A compressed archive can declare far more content than it holds: a few
 * hundred kilobytes of zeros expand to hundreds of megabytes, and an
 * application that validates containers people upload will exhaust its memory
 * on a file it could have refused in a millisecond.
 *
 * The rule is digidoc4j's, so that the two libraries refuse the same archives:
 * expansion is unlimited up to a threshold, and beyond that the total may not
 * exceed the container's own size times a ratio. One megabyte and a hundred to
 * one are their defaults, which leave ordinary documents alone. Text compresses
 * perhaps five to one, and a container of PDFs or images barely compresses at
 * all.
 *
 * The budget is shared across the entries of one container and counted per
 * entry name, so reading the same entry twice costs what it cost the first time
 * rather than twice as much.
 */
final class InflationLimit
{
    public const DEFAULT_THRESHOLD_BYTES = 1_048_576;
    public const DEFAULT_MAX_RATIO = 100;

    /**
     * How much compressed data to feed the decompressor at a time.
     *
     * This is what actually bounds the memory, and it has to be small. PHP's
     * own `gzinflate($data, $max)` is no help: it decompresses the whole stream
     * before noticing the limit, so a 200 MB bomb costs 400 MB of memory before
     * it is refused. Feeding 4 KB at a time caps one step's output at deflate's
     * maximum ratio of about 1032 to 1, so the running total is checked often
     * enough to stop early.
     */
    private const CHUNK_BYTES = 4096;

    /** @var array<string, int> what each entry inflated to */
    private array $inflated = [];

    public function __construct(
        private readonly int $packedBytes,
        private readonly int $thresholdBytes = self::DEFAULT_THRESHOLD_BYTES,
        private readonly int $maxRatio = self::DEFAULT_MAX_RATIO,
        private readonly bool $unlimited = false,
    ) {
        if ($packedBytes < 0) {
            throw new InvalidArgumentException('The packed size cannot be negative');
        }
        if ($thresholdBytes < 0) {
            throw new InvalidArgumentException('The compression ratio threshold cannot be negative');
        }
        if ($maxRatio < 1) {
            throw new InvalidArgumentException('The maximum compression ratio must be at least 1');
        }
    }

    /**
     * No limit at all, for entries this library built itself and for callers
     * who have already decided the bytes are theirs.
     */
    public static function none(): self
    {
        return new self(0, 0, 1, true);
    }

    /**
     * The most this whole container may inflate to.
     */
    public function total(): int
    {
        return $this->unlimited ? \PHP_INT_MAX : max($this->thresholdBytes, $this->packedBytes * $this->maxRatio);
    }

    /**
     * What is left for one entry, given what the others have taken.
     */
    public function remainingFor(string $name): int
    {
        if ($this->unlimited) {
            return \PHP_INT_MAX;
        }
        $used = 0;
        foreach ($this->inflated as $entry => $size) {
            if ($entry !== $name) {
                $used += $size;
            }
        }

        return $this->total() - $used;
    }

    /**
     * Decompress one entry, refusing to go past what is left.
     *
     * @param int $declaredSize the size the archive claims, which is checked
     *                          first because it costs nothing and because an
     *                          honest archive tells the truth there
     *
     * @throws ZipBombException       when the entry would take more than its share
     * @throws UnsupportedZipException when the data is not readable deflate
     */
    public function inflate(string $name, string $packed, int $declaredSize): string
    {
        $allowance = $this->remainingFor($name);
        if ($declaredSize > $allowance) {
            throw new ZipBombException(\sprintf(
                'Entry "%s" says it holds %d bytes, and this container may expand to %d in total. Refusing to decompress it.',
                $name,
                $declaredSize,
                $this->total(),
            ));
        }

        $context = inflate_init(ZLIB_ENCODING_RAW);
        if ($context === false) {
            throw new UnsupportedZipException(\sprintf('Entry "%s" could not be decompressed', $name));
        }

        $out = '';
        $chunks = $packed === '' ? [''] : str_split($packed, self::CHUNK_BYTES);
        $last = \count($chunks) - 1;
        foreach ($chunks as $index => $chunk) {
            $part = @inflate_add($context, $chunk, $index === $last ? ZLIB_FINISH : ZLIB_NO_FLUSH);
            if ($part === false) {
                throw new UnsupportedZipException(\sprintf('Entry "%s" could not be decompressed', $name));
            }
            $out .= $part;
            // Checked inside the loop rather than after it: the whole point is
            // never to hold what the archive was hoping we would hold.
            if (\strlen($out) > $allowance) {
                throw new ZipBombException(\sprintf(
                    'Entry "%s" expands past the %d bytes this container is allowed. Refusing to decompress it.',
                    $name,
                    $this->total(),
                ));
            }
        }

        $this->inflated[$name] = \strlen($out);

        return $out;
    }
}
