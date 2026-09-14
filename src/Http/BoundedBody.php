<?php

declare(strict_types=1);

namespace Allkiri\Http;

/**
 * A response body that stops growing at a limit.
 *
 * Both built-in clients read an answer through one of these, so a server that
 * sends more than it should costs at most the limit in memory. Nothing past
 * the limit is kept: a body cut short is not a smaller valid one, so the
 * clients refuse it rather than return it.
 *
 * @internal
 */
final class BoundedBody
{
    private string $bytes = '';

    private bool $exceeded = false;

    public function __construct(private readonly int $limit) {}

    /**
     * Add the next piece of the body.
     *
     * @return bool false when the piece would pass the limit, and for every piece after that
     */
    public function append(string $chunk): bool
    {
        if ($this->exceeded || \strlen($chunk) > $this->limit - \strlen($this->bytes)) {
            $this->exceeded = true;

            return false;
        }
        $this->bytes .= $chunk;

        return true;
    }

    public function exceeded(): bool
    {
        return $this->exceeded;
    }

    public function bytes(): string
    {
        return $this->bytes;
    }
}
