<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

/**
 * How a Smart-ID session ended, in the service's own vocabulary.
 */
enum SmartIdEndResult: string
{
    case Ok = 'OK';

    /** The person pressed cancel. */
    case UserRefused = 'USER_REFUSED';

    /** The person did not answer in time. */
    case Timeout = 'TIMEOUT';

    /** The account cannot be used: the key is blocked, or the app was reinstalled. */
    case DocumentUnusable = 'DOCUMENT_UNUSABLE';

    /** The person picked the wrong code out of the three the app offered. */
    case WrongVerificationCode = 'WRONG_VC';

    /** Their app is too old for the interaction we asked for. */
    case RequiredInteractionNotSupportedByApp = 'REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP';

    /** They refused at the certificate-choice step. */
    case UserRefusedCertChoice = 'USER_REFUSED_CERT_CHOICE';

    /** They refused at a particular dialogue; `details.interaction` says which. */
    case UserRefusedInteraction = 'USER_REFUSED_INTERACTION';

    /** The app and the service disagreed; nothing the person did. */
    case ProtocolFailure = 'PROTOCOL_FAILURE';

    /** A linked session was expected first. */
    case ExpectedLinkedSession = 'EXPECTED_LINKED_SESSION';

    case ServerError = 'SERVER_ERROR';

    /** The account itself is unusable, not just this document. */
    case AccountUnusable = 'ACCOUNT_UNUSABLE';

    /**
     * English, fit to show the person who was just refused.
     */
    public function message(): string
    {
        return match ($this) {
            self::Ok => 'Done.',
            self::UserRefused, self::UserRefusedInteraction => 'You cancelled the request in the Smart-ID app.',
            self::UserRefusedCertChoice => 'You cancelled while choosing a certificate.',
            self::Timeout => 'The request expired before it was confirmed in the Smart-ID app.',
            self::DocumentUnusable => 'This Smart-ID account cannot be used. Check the Smart-ID app, or the Smart-ID self-service portal.',
            self::WrongVerificationCode => 'The wrong verification code was chosen in the Smart-ID app. Please try again and pick the code shown here.',
            self::RequiredInteractionNotSupportedByApp => 'The Smart-ID app on that device is too old for this request. Please update it.',
            self::ProtocolFailure, self::ServerError => 'Smart-ID could not complete the request. Please try again later.',
            self::ExpectedLinkedSession => 'This request had to follow another Smart-ID session that was not started.',
            self::AccountUnusable => 'This Smart-ID account cannot be used for this request.',
        };
    }

    /**
     * Whether asking again might work. A blocked account or an outdated app
     * will not fix itself by retrying.
     */
    public function isWorthRetrying(): bool
    {
        return match ($this) {
            self::UserRefused, self::UserRefusedInteraction, self::UserRefusedCertChoice,
            self::Timeout, self::WrongVerificationCode, self::ProtocolFailure, self::ServerError => true,
            default => false,
        };
    }
}
