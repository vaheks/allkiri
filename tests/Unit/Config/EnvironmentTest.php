<?php

declare(strict_types=1);

namespace Allkiri\Tests\Unit\Config;

use Allkiri\Config\Environment;
use Allkiri\Crypto\Ocsp\NonceMode;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Every with-method copies the environment through one private helper, which
 * has to tell "not given" apart from "set to null" for three fields. A mistake
 * there shows up far from its cause: a SiVa URL or a list of lists quietly
 * coming back after an unrelated change, or quietly disappearing.
 */
#[CoversNothing]
final class EnvironmentTest extends TestCase
{
    /**
     * The demo environment with its three nullable fields null.
     */
    private static function withNulls(): Environment
    {
        return Environment::demo()->withOcspDefaultUrl(null)->withSivaUrl(null)->withListOfLists(null);
    }

    /**
     * The demo environment with its three nullable fields set.
     */
    private static function withValues(): Environment
    {
        return Environment::demo()->withListOfLists(Environment::euListOfLists());
    }

    public function testTheStartingPointsAreWhatTheySay(): void
    {
        $nulls = self::withNulls();
        self::assertNull($nulls->ocspDefaultUrl);
        self::assertNull($nulls->sivaUrl);
        self::assertNull($nulls->listOfLists);

        $values = self::withValues();
        self::assertNotNull($values->ocspDefaultUrl);
        self::assertNotNull($values->sivaUrl);
        self::assertNotNull($values->listOfLists);
    }

    /**
     * Each with-method, the field it owns, and the value it sets there.
     *
     * @return iterable<string, array{string, mixed, \Closure(Environment): Environment}>
     */
    public static function withMethods(): iterable
    {
        yield 'withTrustedListSources' => ['trustedListSources', [], static fn(Environment $environment): Environment => $environment->withTrustedListSources([])];
        yield 'withExtraTrustAnchors' => ['extraTrustAnchors', [], static fn(Environment $environment): Environment => $environment->withExtraTrustAnchors([])];
        yield 'withTsaUrl' => ['tsaUrl', 'http://tsa.example.test', static fn(Environment $environment): Environment => $environment->withTsaUrl('http://tsa.example.test')];
        yield 'withOcspDefaultUrl, a URL' => ['ocspDefaultUrl', 'http://ocsp.example.test', static fn(Environment $environment): Environment => $environment->withOcspDefaultUrl('http://ocsp.example.test')];
        yield 'withOcspDefaultUrl, null' => ['ocspDefaultUrl', null, static fn(Environment $environment): Environment => $environment->withOcspDefaultUrl(null)];

        $overrides = ['CN=Example CA' => 'http://ocsp.example.test'];
        yield 'withOcspUrlOverrides' => ['ocspUrlOverrides', $overrides, static fn(Environment $environment): Environment => $environment->withOcspUrlOverrides($overrides)];

        yield 'withOcspNonceMode' => ['ocspNonceMode', NonceMode::IfPresent, static fn(Environment $environment): Environment => $environment->withOcspNonceMode(NonceMode::IfPresent)];
        yield 'withHttpTimeout' => ['httpTimeoutSeconds', 5, static fn(Environment $environment): Environment => $environment->withHttpTimeout(5)];
        yield 'withSivaUrl, a URL' => ['sivaUrl', 'https://siva.example.test/V3/validate', static fn(Environment $environment): Environment => $environment->withSivaUrl('https://siva.example.test/V3/validate')];
        yield 'withSivaUrl, null' => ['sivaUrl', null, static fn(Environment $environment): Environment => $environment->withSivaUrl(null)];

        $listOfLists = Environment::euListOfLists(['LV']);
        yield 'withListOfLists, a source' => ['listOfLists', $listOfLists, static fn(Environment $environment): Environment => $environment->withListOfLists($listOfLists)];
        yield 'withListOfLists, null' => ['listOfLists', null, static fn(Environment $environment): Environment => $environment->withListOfLists(null)];
    }

    /**
     * @param \Closure(Environment): Environment $with
     */
    #[DataProvider('withMethods')]
    public function testAWithMethodChangesItsOwnFieldAndNothingElse(string $field, mixed $value, \Closure $with): void
    {
        foreach (['null' => self::withNulls(), 'set' => self::withValues()] as $label => $before) {
            $expected = get_object_vars($before);
            $expected[$field] = $value;

            self::assertSame($expected, get_object_vars($with($before)), 'starting with the nullable fields ' . $label);
        }
    }
}
