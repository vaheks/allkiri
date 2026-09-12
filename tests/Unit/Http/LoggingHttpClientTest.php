<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Http;

use Allkiri\Http\HttpClient;
use Allkiri\Http\HttpRequest;
use Allkiri\Http\LoggingHttpClient;
use Allkiri\Http\TransportException;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Tests\Support\RecordingLogger;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

#[CoversClass(LoggingHttpClient::class)]
final class LoggingHttpClientTest extends TestCase
{
    private const MID = 'https://tsp.demo.sk.ee/mid-api';

    private RecordingLogger $logger;

    protected function setUp(): void
    {
        $this->logger = new RecordingLogger();
    }

    private function client(HttpClient $inner, bool $personalData = false, int $maxBodyBytes = 2048): LoggingHttpClient
    {
        return new LoggingHttpClient($inner, $this->logger, $personalData, $maxBodyBytes);
    }

    /**
     * A logged context value, as the string it has to be.
     */
    private function logged(string $key): string
    {
        $value = $this->logger->last()['context'][$key] ?? null;
        self::assertIsString($value);

        return $value;
    }

    private static function answering(string $contentType, string $body, int $status = 200): MockHttpClient
    {
        return (new MockHttpClient())->respond('http', $status, $contentType, $body);
    }

    // --- what is always logged ----------------------------------------------

    public function testEveryCallIsLoggedWithItsOutcomeAndDuration(): void
    {
        $client = $this->client(self::answering('application/json', '{"sessionID":"abc"}'));

        $client->send(HttpRequest::post(self::MID . '/authentication', 'application/json', '{"hash":"x"}'));

        $record = $this->logger->last();
        self::assertSame(LogLevel::INFO, $record['level']);
        self::assertSame('POST', $record['context']['method']);
        self::assertSame(self::MID . '/authentication', $record['context']['url']);
        self::assertSame(200, $record['context']['status']);
        self::assertIsInt($record['context']['ms']);
        self::assertSame(12, $record['context']['requestBytes']);
        self::assertSame(19, $record['context']['responseBytes']);
        self::assertStringContainsString('POST ' . self::MID . '/authentication -> 200', $this->logger->lastLine());
    }

    public function testTheResponseIsReturnedUntouched(): void
    {
        $client = $this->client(self::answering('application/json', '{"state":"RUNNING"}', 201));

        $response = $client->send(HttpRequest::get(self::MID . '/x'));

        self::assertSame(201, $response->status);
        self::assertSame('{"state":"RUNNING"}', $response->body);
        self::assertSame('application/json', $response->header('Content-Type'));
    }

    /**
     * A call that never comes back is the most interesting line in the log, and
     * the exception still has to reach the caller unchanged.
     */
    public function testAFailedCallIsLoggedAsAWarningAndRethrown(): void
    {
        $inner = (new MockHttpClient())->on('https://', static function (): never {
            throw new TransportException('connection timed out');
        });
        $client = $this->client($inner);

        try {
            $client->send(HttpRequest::get(self::MID . '/x'));
            self::fail('the transport failure should have been rethrown');
        } catch (TransportException $e) {
            self::assertSame('connection timed out', $e->getMessage());
        }

        $record = $this->logger->last();
        self::assertSame(LogLevel::WARNING, $record['level']);
        self::assertSame('connection timed out', $record['context']['error']);
        self::assertInstanceOf(TransportException::class, $record['context']['exception']);
        self::assertStringContainsString('failed after', $this->logger->lastLine());
    }

    public function testTheLevelIsConfigurable(): void
    {
        $client = new LoggingHttpClient(self::answering('application/json', '{}'), $this->logger, level: LogLevel::DEBUG);

        $client->send(HttpRequest::get(self::MID . '/x'));

        self::assertSame(LogLevel::DEBUG, $this->logger->last()['level']);
    }

    // --- personal data is off by default ------------------------------------

    public function testBodiesAreNotLoggedByDefault(): void
    {
        $client = $this->client(self::answering('application/json', '{"cert":"MIIB…"}'));

        $client->send(HttpRequest::post(
            self::MID . '/authentication',
            'application/json',
            '{"phoneNumber":"+37200000766","nationalIdentityNumber":"60001019906"}',
        ));

        $context = $this->logger->last()['context'];
        self::assertArrayNotHasKey('requestBody', $context);
        self::assertArrayNotHasKey('responseBody', $context);
        // The sizes are still there, because they say something without saying
        // anything about a person.
        self::assertSame(69, $context['requestBytes']);
    }

    /**
     * Smart-ID names the person in the path, so the path is not safe to log by
     * default either.
     */
    public function testIdentityCodesAreRemovedFromUrlsByDefault(): void
    {
        $client = $this->client(self::answering('application/json', '{}'));

        $client->send(HttpRequest::get('https://rp-api.smart-id.com/v3/signature/certificate/PNOEE-50001029996-MOCK-Q'));

        self::assertSame(
            'https://rp-api.smart-id.com/v3/signature/certificate/PNOEE-[redacted]',
            $this->logger->last()['context']['url'],
        );
    }

    public function testABareIdentityNumberIsRemovedFromAUrl(): void
    {
        $client = $this->client(self::answering('application/json', '{}'));

        $client->send(HttpRequest::get(self::MID . '/certificate/60001019906'));

        self::assertSame(self::MID . '/certificate/[redacted]', $this->logger->last()['context']['url']);
    }

    /**
     * Session identifiers must survive, because they are what ties a log line
     * to one person's attempt.
     */
    public function testSessionIdentifiersAreLeftAlone(): void
    {
        $client = $this->client(self::answering('application/json', '{}'));
        $url = self::MID . '/authentication/session/de305d54-75b4-431b-adb2-eb6b9e546014';

        $client->send(HttpRequest::get($url));

        self::assertSame($url, $this->logger->last()['context']['url']);
    }

    // --- personal data on request -------------------------------------------

    public function testBodiesAreLoggedWhenAskedFor(): void
    {
        $client = $this->client(self::answering('application/json', '{"state":"COMPLETE"}'), personalData: true);

        $client->send(HttpRequest::post(self::MID . '/authentication', 'application/json', '{"phoneNumber":"+37200000766"}'));

        $context = $this->logger->last()['context'];
        self::assertStringContainsString('+37200000766', $this->logged('requestBody'));
        self::assertSame('{"state":"COMPLETE"}', $context['responseBody']);
    }

    public function testTheUrlIsWholeWhenPersonalDataIsAskedFor(): void
    {
        $client = $this->client(self::answering('application/json', '{}'), personalData: true);
        $url = 'https://rp-api.smart-id.com/v3/signature/certificate/PNOEE-50001029996-MOCK-Q';

        $client->send(HttpRequest::get($url));

        self::assertSame($url, $this->logger->last()['context']['url']);
    }

    /**
     * The point of the whole class: a credential is never logged, however much
     * else has been switched on.
     */
    public function testTheRelyingPartyIdentifierIsNeverLogged(): void
    {
        $client = $this->client(self::answering('application/json', '{}'), personalData: true);
        $uuid = '00000000-0000-0000-0000-000000000000';

        $client->send(HttpRequest::post(
            self::MID . '/authentication',
            'application/json',
            json_encode(['relyingPartyUUID' => $uuid, 'relyingPartyName' => 'DEMO', 'hash' => 'abc'], JSON_THROW_ON_ERROR),
        ));

        $body = $this->logged('requestBody');
        self::assertStringNotContainsString($uuid, $body);
        self::assertStringContainsString('[redacted]', $body);
        // The name is not a secret, and it is the useful half for reading a log.
        self::assertStringContainsString('DEMO', $body);
        self::assertStringContainsString('abc', $body);
    }

    public function testASmartIdSessionSecretIsNeverLogged(): void
    {
        $secret = 'aGVsbG8gdGhpcyBpcyBhIHNlY3JldA==';
        $client = $this->client(
            self::answering('application/json', json_encode([
                'sessionID' => 'abc',
                'sessionToken' => 'token',
                'sessionSecret' => $secret,
            ], JSON_THROW_ON_ERROR)),
            personalData: true,
        );

        $client->send(HttpRequest::get('https://rp-api.smart-id.com/v3/authentication/device-link/anonymous'));

        $body = $this->logged('responseBody');
        self::assertStringNotContainsString($secret, $body);
        self::assertStringContainsString('[redacted]', $body);
        self::assertStringContainsString('token', $body);
    }

    public function testASecretIsRedactedWhereverItIsNested(): void
    {
        $redacted = LoggingHttpClient::redact(json_encode([
            'a' => ['b' => [['relyingPartyUUID' => 'secret-one'], ['SESSIONSECRET' => 'secret-two']]],
        ], JSON_THROW_ON_ERROR));

        self::assertStringNotContainsString('secret-one', $redacted);
        self::assertStringNotContainsString('secret-two', $redacted);
        self::assertSame(2, substr_count($redacted, '[redacted]'));
    }

    public function testANonJsonBodyIsLeftAloneByRedaction(): void
    {
        self::assertSame('not json at all', LoggingHttpClient::redact('not json at all'));
    }

    // --- what must not end up in a log line ---------------------------------

    public function testABinaryBodyIsDescribedRatherThanPrinted(): void
    {
        $der = "\x30\x82\x01\x00\x00\x02\x01\x00";
        $client = $this->client(self::answering('application/timestamp-reply', $der), personalData: true);

        $client->send(HttpRequest::post('http://tsa.demo.sk.ee/tsa', 'application/timestamp-query', "\x30\x00\x00"));

        $context = $this->logger->last()['context'];
        self::assertSame('<3 bytes of application/timestamp-query>', $context['requestBody']);
        self::assertSame('<8 bytes of application/timestamp-reply>', $context['responseBody']);
    }

    public function testALongBodyIsTruncatedAndSaysHowLongItWas(): void
    {
        $long = json_encode(['x' => str_repeat('y', 5000)], JSON_THROW_ON_ERROR);
        $client = $this->client(self::answering('application/json', $long), personalData: true, maxBodyBytes: 64);

        $client->send(HttpRequest::get('https://open-eid.github.io/test-TL/EE_T.xml'));

        $body = $this->logged('responseBody');
        self::assertMatchesRegularExpression('/… \(\d{4} bytes total\)$/', $body);
        self::assertLessThan(200, \strlen($body));
    }

    /**
     * Cutting a UTF-8 body at a byte boundary can produce invalid UTF-8, which
     * some log backends refuse outright.
     */
    public function testTruncationDoesNotSplitACharacter(): void
    {
        $body = json_encode(['t' => str_repeat('õ', 200)], JSON_THROW_ON_ERROR);
        $client = $this->client(self::answering('application/json', $body), personalData: true, maxBodyBytes: 11);

        $client->send(HttpRequest::get('https://example.org/x'));

        $logged = $this->logged('responseBody');
        self::assertTrue(mb_check_encoding($logged, 'UTF-8'));
    }

    public function testAnEmptyBodyIsLoggedAsNothing(): void
    {
        $client = $this->client(self::answering('application/json', ''), personalData: true);

        $client->send(HttpRequest::get('https://example.org/x'));

        self::assertSame('', $this->logger->last()['context']['responseBody']);
    }

    public function testTheBodyLimitMustBePositive(): void
    {
        $this->expectException(\Allkiri\Exception\InvalidArgumentException::class);

        new LoggingHttpClient(new MockHttpClient(), $this->logger, maxBodyBytes: 0);
    }

    // --- the whole library through one of these -----------------------------

    /**
     * Every remote call the library makes goes through the client it was given,
     * so wrapping that one object is enough to see all of them.
     */
    public function testWrappingTheClientCoversEveryServiceTheLibraryCalls(): void
    {
        $inner = (new MockHttpClient())
            ->respond('http://tsa.', 200, 'application/timestamp-reply', 'x')
            ->respond('http://demo.sk.ee/ocsp', 200, 'application/ocsp-response', 'x')
            ->respond('https://tsp.demo.sk.ee', 200, 'application/json', '{}');
        $client = $this->client($inner);

        $client->send(HttpRequest::post('http://tsa.demo.sk.ee/tsa', 'application/timestamp-query', 'q'));
        $client->send(HttpRequest::post('http://demo.sk.ee/ocsp', 'application/ocsp-request', 'q'));
        $client->send(HttpRequest::post('https://tsp.demo.sk.ee/mid-api/signature', 'application/json', '{}'));

        self::assertCount(3, $this->logger->records);
        $urls = [];
        foreach ($this->logger->records as $record) {
            $url = $record['context']['url'] ?? null;
            self::assertIsString($url);
            $urls[] = $url;
        }
        self::assertSame([
            'http://tsa.demo.sk.ee/tsa',
            'http://demo.sk.ee/ocsp',
            'https://tsp.demo.sk.ee/mid-api/signature',
        ], $urls);
    }
}
