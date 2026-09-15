<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

use Allkiri\Exception\InvalidArgumentException;

/**
 * The interaction list as the request carries it: base64 of a JSON array.
 *
 * The exact base64 string matters beyond transport. The authentication
 * protocol signs a digest of it, so the string that was sent has to be kept
 * and reused, not rebuilt: a different key order or a different escape would
 * digest differently and the signature would not verify.
 */
final readonly class Interactions implements \JsonSerializable
{
    /**
     * @param non-empty-list<Interaction> $interactions in order of preference
     */
    private function __construct(
        public array $interactions,
        public string $encoded,
    ) {}

    public static function of(Interaction ...$interactions): self
    {
        if ($interactions === []) {
            throw new InvalidArgumentException('A Smart-ID request needs at least one interaction');
        }

        $json = json_encode(array_values($interactions), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);

        return new self(array_values($interactions), base64_encode($json));
    }

    /**
     * The three dialogues for one sentence, strongest first.
     *
     * The verification-code choice comes first, because a person who is not
     * looking at your page cannot tell which of its three codes to press. Then
     * the same sentence on a screen of its own, then the plain PIN dialogue.
     * The PIN dialogue holds only 60 characters, so a longer sentence needs a
     * shorter text for it. Nothing is cut to fit: a person reads exactly what
     * you wrote, or the list is refused.
     *
     * The authenticator's and the signer's device-link methods drop the
     * verification-code choice, which a device link cannot show;
     * `SmartIdClient` sends the list as given.
     *
     * @param string      $text    up to 200 characters
     * @param string|null $pinText up to 60 characters; `$text` when null
     *
     * @throws InvalidArgumentException when a text is empty, not UTF-8 or too long
     */
    public static function forText(string $text, ?string $pinText = null): self
    {
        $choice = Interaction::confirmationMessageAndVerificationCodeChoice($text);
        $confirmation = Interaction::confirmationMessage($text);

        $pinLimit = InteractionType::DisplayTextAndPin->maximumLength();
        if ($pinText === null && mb_strlen($text, 'UTF-8') > $pinLimit) {
            throw new InvalidArgumentException(\sprintf(
                'The PIN dialogue shows at most %d characters and the text has %d; give it a shorter text of its own',
                $pinLimit,
                mb_strlen($text, 'UTF-8'),
            ));
        }

        return self::of($choice, $confirmation, Interaction::displayTextAndPin($pinText ?? $text));
    }

    /**
     * The same list, restricted to what device-link flows accept.
     *
     * @throws InvalidArgumentException when nothing would be left
     */
    public function forDeviceLink(): self
    {
        $supported = array_values(array_filter(
            $this->interactions,
            static fn(Interaction $i): bool => $i->type->isSupportedInDeviceLink(),
        ));
        if ($supported === []) {
            throw new InvalidArgumentException('Device-link flows cannot show a verification-code choice; add another interaction');
        }

        return self::of(...$supported);
    }

    /**
     * What the signed payload carries: base64 of the SHA-256 of the encoded
     * list.
     */
    public function digest(): string
    {
        return base64_encode(hash('sha256', $this->encoded, true));
    }

    /**
     * Rebuild from a string that was already sent, keeping it byte for byte.
     */
    public static function fromEncoded(string $encoded): self
    {
        $json = base64_decode($encoded, true);
        if ($json === false) {
            throw new InvalidArgumentException('The encoded interactions are not base64');
        }
        $decoded = json_decode($json, true);
        if (!\is_array($decoded) || $decoded === []) {
            throw new InvalidArgumentException('The encoded interactions are not a non-empty JSON array');
        }

        $interactions = [];
        foreach ($decoded as $entry) {
            if (!\is_array($entry)) {
                throw new InvalidArgumentException('An encoded interaction is not an object');
            }
            $type = $entry['type'] ?? null;
            if (!\is_string($type)) {
                throw new InvalidArgumentException('An encoded interaction has no type');
            }
            $interactionType = InteractionType::from($type);
            $text = $entry[$interactionType->textField()] ?? null;
            if (!\is_string($text)) {
                throw new InvalidArgumentException(\sprintf('An encoded interaction has no %s', $interactionType->textField()));
            }
            $interactions[] = new Interaction($interactionType, $text);
        }

        // Keep the string that was sent, not a re-encoding of it.
        return new self($interactions, $encoded);
    }

    public function jsonSerialize(): string
    {
        return $this->encoded;
    }
}
