<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\SmartId;

use Allkiri\SmartId\AcspV2Payload;
use Allkiri\SmartId\FlowType;
use Allkiri\SmartId\InteractionType;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The signed payload, checked against SK's own worked example rather than
 * against a mock service that builds it with this same class.
 *
 * @see https://sk-eid.github.io/smart-id-documentation/rp-api/signature_protocols.html#acsp_v2_digest_calculation
 */
#[CoversClass(AcspV2Payload::class)]
final class AcspV2PayloadTest extends TestCase
{
    /** The interactions of SK's example, Base64 exactly as they were sent. */
    private const INTERACTIONS = 'W3sidHlwZSI6ImNvbmZpcm1hdGlvbk1lc3NhZ2UiLCJkaXNwbGF5VGV4dDIwMCI6IkxvbmdlciBkZXNjcmlwdGlvbiBvZiB0aGUgdHJhbnNhY3Rpb24gY29udGV4dCJ9LHsidHlwZSI6ImRpc3BsYXlUZXh0QW5kUElOIiwiZGlzcGxheVRleHQ2MCI6IlNob3J0IGRlc2NyaXB0aW9uIG9mIHRoZSB0cmFuc2FjdGlvbiBjb250ZXh0In1d';

    private const CALLBACK_URL = 'https://rp.example.com/callback-url?value=RrKjjT4aggzu27YBddX1bQ';

    public function testSksWorkedExampleGivesSksDigest(): void
    {
        $payload = new AcspV2Payload(
            'smart-id',
            'MTlop6EXCrQ6FOErcKjxUhbV',
            'GYS+yoah6emAcVDNIajwSs6UB/M95XrDxMzXBUkwQJ9YFDipXXzGpPc7raWcuc2+TEoRc7WvIZ/7dU/iRXenYg==',
            'GnsWXXEjTCKR89fj9uo5u5ReBZ9JR7_pezLAI5jMS00',
            'REVNTw==',
            'Example RP',
            base64_encode(hash('sha256', self::INTERACTIONS, true)),
            InteractionType::ConfirmationMessage,
            FlowType::Web2App,
            self::CALLBACK_URL,
        );

        self::assertSame(
            'smart-id|ACSP_V2|MTlop6EXCrQ6FOErcKjxUhbV'
            . '|GYS+yoah6emAcVDNIajwSs6UB/M95XrDxMzXBUkwQJ9YFDipXXzGpPc7raWcuc2+TEoRc7WvIZ/7dU/iRXenYg=='
            . '|GnsWXXEjTCKR89fj9uo5u5ReBZ9JR7_pezLAI5jMS00|REVNTw==|RXhhbXBsZSBSUA=='
            . '|RW2HOCLDvRFNWmAOmpWE+3rt7a8q4JGQD3n75d6xJHM=|confirmationMessage'
            . '|https://rp.example.com/callback-url?value=RrKjjT4aggzu27YBddX1bQ|Web2App',
            $payload->bytes(),
        );
        // The digest SK prints for this example, with the SHA-512 it uses.
        self::assertSame(
            'pKOjbNl/5Fy8NfrFqsj6pSn8W8O+Ik8rM33QSsbyD3J9qDJvEm90SboUciuY4wHGWa0Pnq8BgT3NJKmJiUDfKg==',
            base64_encode(hash('sha512', $payload->bytes(), true)),
        );
    }

    /**
     * @return iterable<string, array{FlowType, string}>
     */
    public static function flows(): iterable
    {
        yield 'a QR code signs no callback' => [FlowType::Qr, ''];
        yield 'a notification signs no callback' => [FlowType::Notification, ''];
        yield 'Web2App signs the callback' => [FlowType::Web2App, self::CALLBACK_URL];
        yield 'App2App signs the callback' => [FlowType::App2App, self::CALLBACK_URL];
    }

    #[DataProvider('flows')]
    public function testTheTenthFieldIsTheCallbackUrlOfASameDeviceFlowOnly(FlowType $flow, string $expected): void
    {
        $payload = new AcspV2Payload('smart-id', 'c2VydmVy', 'Y2hhbGxlbmdl', null, 'REVNTw==', null, 'ZGlnZXN0', InteractionType::DisplayTextAndPin, $flow, self::CALLBACK_URL);

        $parts = explode('|', $payload->bytes());

        self::assertCount(11, $parts);
        self::assertSame($expected, $parts[9]);
        self::assertSame($flow->value, $parts[10]);
    }
}
