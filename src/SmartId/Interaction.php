<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Exception\InvalidArgumentException;

/**
 * One dialogue the Smart-ID app should show.
 *
 * A request carries a list of them in order of preference: the app uses the
 * first it understands and reports which one that was.
 */
final readonly class Interaction implements \JsonSerializable
{
    public function __construct(
        public InteractionType $type,
        public string $text,
    ) {
        if ($text === '') {
            throw new InvalidArgumentException(\sprintf('An interaction of type %s needs text', $type->value));
        }
        // It travels as JSON, which cannot carry anything else.
        if (!mb_check_encoding($text, 'UTF-8')) {
            throw new InvalidArgumentException(\sprintf('The text of an interaction of type %s must be UTF-8', $type->value));
        }
        // The service counts characters, and the app truncates nothing: too
        // long is a refused request.
        $length = mb_strlen($text, 'UTF-8');
        if ($length > $type->maximumLength()) {
            throw new InvalidArgumentException(\sprintf(
                '%s allows %d characters, got %d',
                $type->textField(),
                $type->maximumLength(),
                $length,
            ));
        }
    }

    public static function displayTextAndPin(string $text): self
    {
        return new self(InteractionType::DisplayTextAndPin, $text);
    }

    public static function confirmationMessage(string $text): self
    {
        return new self(InteractionType::ConfirmationMessage, $text);
    }

    /**
     * The app offers three codes and the person must pick the one shown here.
     */
    public static function confirmationMessageAndVerificationCodeChoice(string $text): self
    {
        return new self(InteractionType::ConfirmationMessageAndVerificationCodeChoice, $text);
    }

    /**
     * @return array<string, string>
     */
    public function jsonSerialize(): array
    {
        return ['type' => $this->type->value, $this->type->textField() => $this->text];
    }
}
