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
        $record = $this->last();
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
