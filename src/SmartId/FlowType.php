<?php

declare(strict_types=1);

namespace Allkiri\SmartId;

/**
 * How the person reached the Smart-ID app.
 *
 * The service reports it, and it goes into the signed payload of an
 * authentication, so a session started as a QR code cannot be completed as
 * though it had been a push notification.
 */
enum FlowType: string
{
    case Qr = 'QR';
    case Web2App = 'Web2App';
    case App2App = 'App2App';
    case Notification = 'Notification';

    public function isDeviceLink(): bool
    {
        return $this !== self::Notification;
    }
}
