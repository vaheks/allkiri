<?php

declare(strict_types=1);

namespace Allkiri\Http;

/**
 * No HTTP response was obtained: DNS, connection, TLS handshake, pinning
 * mismatch or timeout. The message carries the transport's own wording.
 */
final class TransportException extends HttpException {}
