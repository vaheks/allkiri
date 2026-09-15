<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Signing;

use Allkiri\Crypto\Ocsp\OcspClient;
use Allkiri\Crypto\Tsp\TspClient;
use Allkiri\Signing\LtExtender;
use Allkiri\Signing\SignatureLevel;
use Allkiri\Signing\SigningException;
use Allkiri\Tests\Support\Clock\FrozenClock;
use Allkiri\Tests\Support\Http\MockHttpClient;
use Allkiri\Tests\Support\Pki\TestPki;
use Allkiri\Trust\ChainBuilder;
use Allkiri\Trust\InMemoryTrustStore;
use Allkiri\Xades\SignatureDocument;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(LtExtender::class)]
final class LtExtenderTest extends TestCase
{
    /**
     * #11: asked for LTA, it said archive timestamps were not implemented,
     * although they are. They are only not this class's job.
     */
    public function testAskedForLtaItPointsToWhatAddsTheArchiveTimestamp(): void
    {
        $http = new MockHttpClient();
        $store = new InMemoryTrustStore([]);
        $extender = new LtExtender(new TspClient($http, 'http://tsa.allkiri.test/'), new OcspClient($http, new FrozenClock()), new ChainBuilder($store), $store);
        $document = SignatureDocument::parse('<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"/>');
        $signature = $document->signatures()[0] ?? throw new \LogicException('The test document has no signature');

        try {
            $extender->extend($document, $signature, TestPki::signerEc256()->certificate, SignatureLevel::LTA);
            self::fail('LtExtender took on an archive timestamp');
        } catch (SigningException $exception) {
            self::assertStringContainsString('LtaExtender', $exception->getMessage());
            self::assertStringNotContainsString('not implemented', $exception->getMessage());
        }
        self::assertSame([], $http->requests(), 'nothing was asked of a service');
    }
}
