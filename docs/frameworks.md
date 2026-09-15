# Wiring it into a framework

The library has no framework integration and needs none. There is one object to
build, `Allkiri`, and it takes everything it needs through its constructor:

```php
new Allkiri(
    Environment::production(),
    $http,      // HttpClient, or null for the built-in cURL one
    $clock,     // PSR-20, defaults to the system clock
    $cache,     // PSR-16, for trusted lists; strongly recommended
    $policy,    // ValidationPolicy
    $nonces,    // NonceGenerator
    $logger,    // PSR-3
    $reader,    // AsicReader, when its limits on containers need changing
    600,        // seconds a prepared signature may wait for its value
);
```

Everything else hangs off it. Nothing is static, nothing is global, and nothing
touches a session, a file or a database on its own.

Mobile-ID and Smart-ID each take their own configuration object, and so does
Web eID sign-in, passed per call rather than held:
`$allkiri->mobileIdSigner($configuration)`. Web eID signing needs none. Register
those configurations as services too, because the Mobile-ID and Smart-ID ones
carry your relying-party credentials.

## Laravel

A service provider, once:

```php
// app/Providers/AllkiriServiceProvider.php
use Allkiri\Allkiri;
use Allkiri\Config\Environment;
use Allkiri\MobileId\MobileIdConfiguration;
use Allkiri\SmartId\SmartIdConfiguration;
use Allkiri\WebEid\WebEidConfiguration;
use Allkiri\WebEid\WebEidOrigin;
use Illuminate\Contracts\Cache\Repository;
use Psr\SimpleCache\CacheInterface;

public function register(): void
{
    $this->app->singleton(Allkiri::class, function ($app) {
        $live = $app['config']->get('allkiri.live');

        return new Allkiri(
            $live ? Environment::production() : Environment::demo(),
            null,
            new \Allkiri\Clock\SystemClock(),
            // Laravel's cache repository is PSR-16 from Laravel 9 onwards.
            // On anything older, wrap the store yourself.
            $app->make(Repository::class),
            logger: \Log::getLogger(),
        );
    });

    $this->app->singleton(MobileIdConfiguration::class, fn ($app) => $app['config']->get('allkiri.live')
        ? MobileIdConfiguration::production(
            $app['config']->get('allkiri.mobile_id.uuid'),
            $app['config']->get('allkiri.mobile_id.name'),
            'Sign the contract',
        )
        : MobileIdConfiguration::demo('Sign the contract'));

    $this->app->singleton(SmartIdConfiguration::class, fn ($app) => $app['config']->get('allkiri.live')
        ? SmartIdConfiguration::production(
            $app['config']->get('allkiri.smart_id.uuid'),
            $app['config']->get('allkiri.smart_id.name'),
        )
        : SmartIdConfiguration::demo());

    $this->app->singleton(WebEidConfiguration::class, fn ($app) => new WebEidConfiguration(
        WebEidOrigin::parse($app['config']->get('app.url')),
    ));
}
```

`config/allkiri.php` reads the credentials from the environment:

```php
return [
    'live' => env('ALLKIRI_MODE', 'demo') === 'live',
    'mobile_id' => ['uuid' => env('MID_RP_UUID'), 'name' => env('MID_RP_NAME')],
    'smart_id' => ['uuid' => env('SID_RP_UUID'), 'name' => env('SID_RP_NAME')],
];
```

Then a controller is ordinary Laravel:

```php
public function start(Request $request, Allkiri $allkiri, MobileIdConfiguration $configuration)
{
    $session = $allkiri->mobileIdAuthenticator($configuration)->start(new MobileIdIdentity(
        $request->string('phone'),
        $request->string('identityCode'),
    ));

    $request->session()->put('mid', json_encode($session));

    return ['verificationCode' => $session->verificationCode];
}
```

Two Laravel-specific points.

**The origin must match exactly.** `WebEidOrigin::parse(config('app.url'))`
works only when `APP_URL` is what the browser actually reports as
`location.origin`, scheme and port included. Behind a proxy that terminates TLS,
set `TrustProxies` correctly or the card will sign an origin your server does
not recognise.

**Polling endpoints hold a request open.** Both Mobile-ID and Smart-ID let the
service keep a status request open for up to ten seconds by default. With the
`file` or `database` session driver, Laravel holds an exclusive session lock for
that whole time and every other request from that browser queues behind it. Use
Redis, or release the lock in the polling route:

```php
Route::post('/mid/poll', PollController::class)->middleware('web');
// in the controller, before the long call:
$request->session()->save();
```

## Symfony

The mode is one word, so give it a two-line factory rather than trying to
express the choice in YAML:

```php
// src/Allkiri/EnvironmentFactory.php
namespace App\Allkiri;

use Allkiri\Config\Environment;

final class EnvironmentFactory
{
    public static function create(string $mode): Environment
    {
        // One explicit word rather than a boolean. "ALLKIRI_MODE=false" is a
        // non-empty string, and reads as true in a careless check.
        return $mode === 'live' ? Environment::production() : Environment::demo();
    }
}
```

Then, in `config/services.yaml`:

```yaml
parameters:
    allkiri.mode: '%env(ALLKIRI_MODE)%'

services:
    Allkiri\Config\Environment:
        factory: ['App\Allkiri\EnvironmentFactory', 'create']
        arguments: ['%allkiri.mode%']

    Allkiri\Allkiri:
        arguments:
            $environment: '@Allkiri\Config\Environment'
            $http: null
            $cache: '@allkiri.cache'
            $logger: '@logger'

    allkiri.cache:
        class: Symfony\Component\Cache\Psr16Cache
        arguments: ['@cache.app']

    Allkiri\MobileId\MobileIdConfiguration:
        factory: ['Allkiri\MobileId\MobileIdConfiguration', 'production']
        arguments: ['%env(MID_RP_UUID)%', '%env(MID_RP_NAME)%', 'Sign the contract']

    Allkiri\SmartId\SmartIdConfiguration:
        factory: ['Allkiri\SmartId\SmartIdConfiguration', 'production']
        arguments: ['%env(SID_RP_UUID)%', '%env(SID_RP_NAME)%']

    Allkiri\WebEid\WebEidConfiguration:
        arguments:
            $origin: '@allkiri.origin'

    allkiri.origin:
        class: Allkiri\WebEid\WebEidOrigin
        factory: ['Allkiri\WebEid\WebEidOrigin', 'parse']
        arguments: ['%env(APP_ORIGIN)%']
```

`Environment::demo()` and `Environment::production()` are the only switch
between the free test services and the real ones. Keep it in configuration, so
that nothing but an environment variable separates the two, and make that one
variable decide the relying-party credentials as well. A setup where the
services are live and the credentials are not, or the reverse, fails somewhere
deep inside a signature rather than at boot.

`examples/demo-app/config.php` is the whole idea in one readable file: two
modes, five required values in the live one, and a refusal to start rather than
a fallback.

To use Symfony's HTTP client instead of the built-in one, wrap it:

```php
new Allkiri($environment, new \Allkiri\Http\Psr18HttpClient($psr18Client, $requestFactory, $streamFactory));
```

The adapter refuses an answer larger than 16 MiB, or the limit you pass as its
fourth argument. That bounds the copy allkiri makes, not the body the PSR-18
client may already have read into memory before returning it, so set a limit
on the client too if a hostile server is part of your threat model. The
built-in cURL client bounds the download itself.

Symfony sessions do not lock by default, so the polling concern above does not
arise.

## Anything else

Plain PHP, Slim, Mezzio, a queue worker: build one `Allkiri`, keep it, and pass
the configuration objects where they are needed. `examples/demo-app` is exactly
that, with no framework at all: one file of endpoints and one of configuration.

## What to cache, and what not to

**Cache the trusted lists.** Without a PSR-16 cache, the European list of lists
and every national list beneath it are fetched on the first call that needs
trust, which is slow and rude to the publishers. Give it a cache with a store
that survives deploys. The library handles expiry itself.

**Never cache a session.** `MobileIdSession`, `SmartIdSession`,
`WebEidSigningSession` and the signing sessions are per person and per attempt.
They serialise to JSON so you can keep them in a PHP session or a database row
between two requests. Two of them carry secrets that must not reach a browser:
the Smart-ID session secret, and the Web eID challenge.

**Never cache a container you are signing.** The signing session is bound to the
exact set of data files by a fingerprint, so a container that changes underneath
makes `finalize()` refuse. That is the intended behaviour, not an obstacle to
work around.

## Long-running processes

`Allkiri` holds no per-request state, so it is safe in Swoole, RoadRunner,
FrankenPHP or Octane. The trusted list it loads is cached in memory for the
process lifetime as well as in your PSR-16 store, which is what you want.

Two things to watch: the clock, if you injected something that freezes, and the
logger, if it holds a request-scoped context. Both are constructor arguments, so
resetting them is a matter of rebuilding the one object.

## The browser side

Serve `assets/allkiri.js` and `assets/allkiri-qr.js` from your public directory
or straight from `vendor/vaheks/allkiri/assets/`. They are plain scripts with no
build step; see [browser.md](browser.md). If you bundle, both files are also
CommonJS modules.

For Laravel Vite, the simplest route is a copy step in `composer.json`:

```json
"post-autoload-dump": [
    "@php -r \"@copy('vendor/vaheks/allkiri/assets/allkiri.js', 'public/js/allkiri.js');\""
]
```
