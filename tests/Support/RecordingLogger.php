<?php

declare(strict_types=1);

namespace Allkiri\Tests\Support;

use Psr\Log\AbstractLogger;

/**
 * A PSR-3 logger that keeps what it was told, so a test can assert on it.
 *
 * @phpstan-type Record array{level: string, message: string, context: array<string, mixed>}
 */
final class RecordingLogger extends AbstractLogger
{
    /** @var list<array{level: string, message: string, context: array<mixed>}> */
    public array $records = [];

    /**
     * @param array<mixed> $context
     */
    public function log(mixed $level, string|\Stringable $message, array $context = []): void
    {
        $this->records[] = [
            'level' => \is_string($level) ? $level : 'unknown',
            'message' => (string) $message,
            'context' => $context,
        ];
    }

    /**
     * @return array{level: string, message: string, context: array<mixed>}
     */
    public function last(): array
    {
        $last = end($this->records);
        if ($last === false) {
            throw new \RuntimeException('Nothing was logged');
        }

        return $last;
    }

    /**
     * The message with its {placeholders} filled in, which is what a log file
     * would actually contain.
     */
    public function lastLine(): string
    {
        return self::filled($this->last());
    }

    /**
     * Everything a log backend could print from what was recorded: each message
     * with its placeholders filled in, every string in its context, and every
     * exception as PHP prints it, which includes the whole chain and the trace.
     *
     * A test that something never reaches a log asserts on this, not on one
     * field of one record.
     */
    public function transcript(): string
    {
        $lines = [];
        foreach ($this->records as $record) {
            $lines[] = self::filled($record);
            foreach ($record['context'] as $value) {
                if (\is_string($value)) {
                    $lines[] = $value;
                } elseif ($value instanceof \Throwable) {
                    $lines[] = (string) $value;
                }
            }
        }

        return implode("\n", $lines);
    }

    /**
     * @param array{level: string, message: string, context: array<mixed>} $record
     */
    private static function filled(array $record): string
    {
        $line = $record['message'];
        foreach ($record['context'] as $key => $value) {
            $replacement = match (true) {
                \is_string($value) => $value,
                \is_bool($value) => $value ? 'true' : 'false',
                \is_int($value), \is_float($value) => (string) $value,
                $value instanceof \Stringable => $value->__toString(),
                default => null,
            };
            if ($replacement !== null) {
                $line = str_replace('{' . $key . '}', $replacement, $line);
            }
        }

        return $line;
    }
}
