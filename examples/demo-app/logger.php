<?php

declare(strict_types=1);

/**
 * A PSR-3 logger in thirty lines, writing one JSON object per line.
 *
 * It exists so the demo has somewhere to log without pulling in Monolog, and so
 * the shape of a useful record is visible: a timestamp, a level, a message with
 * its placeholders intact, and the context as structured data rather than as
 * prose. That is what makes a log answerable by a query.
 *
 * A real application uses its framework's logger, and JSON lines are one
 * `COPY` away from a Postgres table or an `INSERT` away from MySQL. Nothing
 * about allkiri cares which: it takes any PSR-3 implementation.
 */

namespace Allkiri\Demo;

use Psr\Log\AbstractLogger;

final class FileLogger extends AbstractLogger
{
    public function __construct(private readonly string $path)
    {
        // Checked once, here, rather than discovered on every line.
        //
        // A logger that cannot write emits a PHP warning per call, and with
        // display_errors on a development machine that warning goes into the
        // HTTP response body, ahead of the JSON. The browser then cannot read
        // an answer it was given, which surfaces minutes later as an
        // authentication that appears to fail when it actually succeeded.
        // Refusing at boot costs one line and prevents all of that.
        $directory = \dirname($path);
        if (!is_dir($directory)) {
            throw new \RuntimeException(\sprintf(
                'ALLKIRI_LOG is "%s", but the directory "%s" does not exist. Create it, or point at a file somewhere that does.',
                $path,
                $directory,
            ));
        }
        if (file_exists($path) ? !is_writable($path) : !is_writable($directory)) {
            throw new \RuntimeException(\sprintf('ALLKIRI_LOG is "%s", which cannot be written to.', $path));
        }
    }

    /**
     * @param array<mixed> $context
     */
    public function log(mixed $level, string|\Stringable $message, array $context = []): void
    {
        $record = [
            'time' => (new \DateTimeImmutable())->format(\DATE_ATOM),
            'level' => self::levelName($level),
            // The template, not the filled-in sentence: two thousand lines that
            // differ only in their context are one query, and two thousand
            // unique sentences are a text search.
            'message' => (string) $message,
            'context' => self::loggable($context),
        ];

        $line = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($line === false) {
            return;
        }
        file_put_contents($this->path, $line . "\n", FILE_APPEND | LOCK_EX);
    }

    /**
     * PSR-3 types the level as mixed, and its own constants are strings.
     */
    private static function levelName(mixed $level): string
    {
        if (\is_string($level)) {
            return $level;
        }

        return $level instanceof \Stringable ? $level->__toString() : 'unknown';
    }

    /**
     * Context can hold anything, including exceptions and binary strings.
     *
     * @param array<array-key, mixed> $context
     *
     * @return array<array-key, mixed>
     */
    private static function loggable(array $context): array
    {
        $result = [];
        foreach ($context as $key => $value) {
            $result[$key] = match (true) {
                $value instanceof \Throwable => ['class' => $value::class, 'message' => $value->getMessage()],
                $value instanceof \DateTimeInterface => $value->format(\DATE_ATOM),
                $value instanceof \Stringable => (string) $value,
                \is_array($value) => self::loggable($value),
                \is_string($value) && !mb_check_encoding($value, 'UTF-8') => \sprintf('<%d bytes>', \strlen($value)),
                default => $value,
            };
        }

        return $result;
    }
}
