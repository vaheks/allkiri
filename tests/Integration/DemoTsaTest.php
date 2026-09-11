<?php

declare(strict_types=1);

namespace Allkiri\Tests\Integration;

use Allkiri\Clock\SystemClock;
use Allkiri\Config\Environment;
use Allkiri\Crypto\HashAlgorithm;
use Allkiri\Crypto\Tsp\TimestampTokenVerifier;
use Allkiri\Crypto\Tsp\TspClient;
use Allkiri\Trust\ChainBuilder;
use Allkiri\Trust\ServiceType;
use Allkiri\Trust\TrustedList\TrustedListLoader;
use Allkiri\Trust\TrustedListTrustStore;

/**
 * SK's free demo timestamp service, as it actually behaves.
 */
final class DemoTsaTest extends IntegrationTestCase
{
    public function testADemoTimestampIsObtainedAndVerifies(): void
    {
        $environment = Environment::demo();
        $client = new TspClient(self::http(20), $environment->tsaUrl);
        $data = 'allkiri integration test ' . bin2hex(random_bytes(8));

        $result = $client->timestamp($data);

        self::assertSame(HashAlgorithm::SHA256->digest($data), $result->token->tstInfo()->messageImprint);
        self::assertStringContainsString('TIMESTAMPING', (string) $result->tsaCertificate->commonName());
        self::assertTrue($result->tsaCertificate->hasExtendedKeyUsage('id-kp-timeStamping'));
        self::assertLessThan(300, abs($result->genTime()->getTimestamp() - time()), 'the TSA clock agrees with ours');

        // Verifying again from the token's own bytes must give the same answer.
        $again = (new TimestampTokenVerifier())->verify(
            \Allkiri\Crypto\Tsp\TimestampToken::fromDer($result->token->der()),
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA256->digest($data),
        );
        self::assertSame($result->genTime()->format(DATE_ATOM), $again->genTime()->format(DATE_ATOM));
    }

    public function testTheDemoTsaIsInTheTestTrustedList(): void
    {
        $environment = Environment::demo();
        $http = self::http(30);
        $client = new TspClient($http, $environment->tsaUrl);
        $result = $client->timestamp('allkiri trust check');

        $store = new TrustedListTrustStore(new TrustedListLoader($http, clock: new SystemClock()), $environment->trustedListSources);
        $chain = (new ChainBuilder($store))->build(
            $result->tsaCertificate,
            $result->token->signedData()->certificates(),
            $result->genTime(),
            ServiceType::tsaTypes(),
        );

        self::assertGreaterThanOrEqual(1, $chain->length());
        self::assertTrue($chain->anchor->serviceType->isTsa());
    }
}
