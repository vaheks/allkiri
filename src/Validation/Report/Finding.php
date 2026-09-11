<?php

declare(strict_types=1);

namespace Allkiri\Validation\Report;

/**
 * One thing the validator noticed. The code is the stable part that callers
 * may branch on; the message is for people.
 */
final readonly class Finding implements \JsonSerializable
{
    private function __construct(
        public string $code,
        public string $message,
        public Severity $severity,
        public ?Indication $indication = null,
        public ?SubIndication $subIndication = null,
    ) {}

    public static function error(string $code, string $message, Indication $indication, SubIndication $subIndication): self
    {
        return new self($code, $message, Severity::Error, $indication, $subIndication);
    }

    public static function warning(string $code, string $message): self
    {
        return new self($code, $message, Severity::Warning);
    }

    public static function info(string $code, string $message): self
    {
        return new self($code, $message, Severity::Info);
    }

    /**
     * @return array<string, string>
     */
    public function jsonSerialize(): array
    {
        $data = ['code' => $this->code, 'message' => $this->message, 'severity' => $this->severity->value];
        if ($this->indication !== null) {
            $data['indication'] = $this->indication->value;
        }
        if ($this->subIndication !== null) {
            $data['subIndication'] = $this->subIndication->value;
        }

        return $data;
    }
}
