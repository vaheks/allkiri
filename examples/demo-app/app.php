<?php

declare(strict_types=1);

/**
 * The demo application's server side: one file, plain PHP, no framework.
 *
 * It is deliberately small enough to read in one sitting, because its job is to
 * show what an application has to do rather than to be an application. Every
 * endpoint is a few lines, and the interesting parts are commented.
 *
 * What it stores in `$_SESSION` is what a real application would store
 * somewhere: the challenge, the signing session, the container being signed.
 * The library never touches sessions itself.
 *
 * Not for production. It refuses cross-site requests with a token of its own,
 * where a real application would use its framework's protection, and it has no
 * accounts, no authorisation and no rate limiting. It keeps uploaded files in
 * var/ beside this file and never deletes them.
 *
 * Which services it talks to, and whose credentials it uses, is decided in
 * config.php. That is the only file here that reads the environment.
 */

namespace Allkiri\Demo;

use Allkiri\Allkiri;
use Allkiri\Container\AsicContainer;
use Allkiri\Container\DataFile;
use Allkiri\Http\CurlHttpClient;
use Allkiri\Http\LoggingHttpClient;
use Allkiri\MobileId\MobileIdIdentity;
use Allkiri\MobileId\MobileIdResult;
use Allkiri\MobileId\MobileIdSession;
use Allkiri\MobileId\MobileIdSessionException;
use Allkiri\MobileId\MobileIdSessionStatus;
use Allkiri\MobileId\MobileIdSigningSession;
use Allkiri\SmartId\CertificateLevel;
use Allkiri\SmartId\DeviceLink;
use Allkiri\SmartId\FlowType;
use Allkiri\SmartId\Interactions;
use Allkiri\SmartId\SemanticsIdentifier;
use Allkiri\SmartId\SmartIdCallback;
use Allkiri\SmartId\SmartIdConfiguration;
use Allkiri\SmartId\SmartIdSession;
use Allkiri\SmartId\SmartIdSessionStatus;
use Allkiri\SmartId\SmartIdSigningSession;
use Allkiri\Validation\Report\ReportRenderer;
use Allkiri\WebEid\CardAlgorithm;
use Allkiri\WebEid\WebEidChallenge;
use Allkiri\WebEid\WebEidSigningSession;

final class App
{
    /** How long a finished poll's answer is given again. See pollWithoutTheLock(). */
    private const REPEAT_SECONDS = 60;

    private readonly Allkiri $allkiri;

    private readonly Config $config;

    public function __construct(?Config $configuration = null)
    {
        // Which services, and whose credentials, is the one decision that has
        // to be made before anything else. See config.php.
        $this->config = $configuration ?? Config::fromEnvironment();

        // ALLKIRI_CA_BUNDLE is only needed where PHP has no curl.cainfo set,
        // which is common on Windows and makes every HTTPS call fail with curl
        // error 60. A properly installed PHP needs none of this.
        $http = new CurlHttpClient(30, caBundlePath: $this->config->caBundle);

        // One wrapper, and every remote call the library makes is logged:
        // Mobile-ID, Smart-ID, timestamps, revocation checks, trusted lists.
        if ($this->config->logHttp) {
            $http = new LoggingHttpClient($http, $this->config->logger, $this->config->logPersonalData);
        }

        $this->allkiri = new Allkiri($this->config->environment, $http, logger: $this->config->logger);
    }

    public function config(): Config
    {
        return $this->config;
    }

    // --- the three means, for signing in ------------------------------------

    /**
     * @return array<string, mixed>
     */
    public function cardChallenge(): array
    {
        $challenge = $this->allkiri->webEidAuthenticator($this->config->webEid)->challenge();
        // Against the browser session that asked, and used once. The token
        // carries no challenge, so this binding is what ties an answer to the
        // browser that started it.
        $_SESSION['web-eid'] = json_encode($challenge, JSON_THROW_ON_ERROR);
        $this->audit('card challenge issued');

        return ['nonce' => $challenge->nonce];
    }

    /**
     * @param array<string, mixed> $request
     *
     * @return array<string, mixed>
     */
    public function cardLogin(array $request): array
    {
        $stored = $_SESSION['web-eid'] ?? null;
        unset($_SESSION['web-eid']);
        if (!\is_string($stored)) {
            throw new \RuntimeException('No challenge was issued to this browser');
        }

        $identity = $this->allkiri->webEidAuthenticator($this->config->webEid)->validate(
            self::string($request, 'token'),
            WebEidChallenge::fromJson($stored),
        );

        return $this->signedIn($identity);
    }

    /**
     * @param array<string, mixed> $request
     *
     * @return array<string, mixed>
     */
    public function mobileIdLoginStart(array $request): array
    {
        $authenticator = $this->allkiri->mobileIdAuthenticator($this->config->mobileId);
        $session = $authenticator->start(new MobileIdIdentity(
            self::string($request, 'phoneNumber'),
            self::string($request, 'identityCode'),
        ));
        $_SESSION['mobile-id'] = json_encode($session, JSON_THROW_ON_ERROR);
        $this->forgetFinished('mobile-id');
        $this->audit('authentication started', [
            'mean' => 'mobile-id',
            'session' => $session->sessionId,
            'identity' => $session->identity->nationalIdentityNumber,
        ]);

        // Show this before the person touches their phone: it is the only thing
        // telling them the request is the one they started here.
        return ['verificationCode' => $session->verificationCode];
    }

    /**
     * @return array<string, mixed>
     */
    public function mobileIdLoginPoll(): array
    {
        return $this->pollWithoutTheLock(
            'mobile-id',
            'No Mobile-ID session is in progress',
            function (string $stored): ?MobileIdSessionStatus {
                $session = MobileIdSession::fromJson($stored);
                $status = $this->allkiri->mobileIdClient($this->config->mobileId)->status($session->type, $session->sessionId);

                return $status->isRunning() ? null : $status;
            },
            function (string $stored, MobileIdSessionStatus $status): array {
                // What MobileIdAuthenticator::poll() does before completing.
                if (!$status->isOk()) {
                    throw new MobileIdSessionException($status->result ?? MobileIdResult::Timeout);
                }
                $identity = $this->allkiri->mobileIdAuthenticator($this->config->mobileId)->complete(MobileIdSession::fromJson($stored), $status);

                return ['done' => true] + $this->signedIn($identity);
            },
        );
    }

    /**
     * @param array<string, mixed> $request
     *
     * @return array<string, mixed>
     */
    public function smartIdLoginStart(array $request): array
    {
        $authenticator = $this->allkiri->smartIdAuthenticator($this->config->smartId);
        $session = $authenticator->startNotification(
            SemanticsIdentifier::estonian(self::string($request, 'identityCode')),
            // A relying party's name can be long, so the PIN dialogue gets a
            // short text of its own rather than a cut one.
            self::interactions('Log in to ' . $this->config->serviceName(), 'Log in'),
        );
        $_SESSION['smart-id'] = json_encode($session, JSON_THROW_ON_ERROR);
        $this->forgetFinished('smart-id');
        $this->audit('authentication started', ['mean' => 'smart-id', 'session' => $session->sessionId]);

        return ['verificationCode' => $session->verificationCode];
    }

    /**
     * @return array<string, mixed>
     */
    public function smartIdLoginPoll(): array
    {
        return $this->smartIdSignInPoll('smart-id', 'No Smart-ID session is in progress', null);
    }

    /**
     * Start a Smart-ID sign-in that names nobody: the person is whoever answers,
     * and who they are comes back in the certificate. There is no verification
     * code to show, because the code or the link on this page is what ties the
     * request to it.
     *
     * The page offers it two ways: a QR code for a phone to scan, first on a
     * computer, and a Web2App link that opens the Smart-ID app on the same phone,
     * first on a phone. The app sends the person back to smartIdCallback(). SK
     * wants one session to serve both, and a session a link can finish needs a
     * callback URL, so every one of these gets one. A QR link carries none.
     *
     * It is kept apart from the sign-in by identity code, so either can run
     * while the other does, as Mobile-ID's can.
     *
     * @return array<string, mixed>
     */
    public function smartIdQrLoginStart(): array
    {
        // A random value in the URL, kept with the session in this browser's own
        // session, is what ties the returning browser to this one.
        $callbackUrl = SmartIdCallback::initialUrl($this->config->webEid->origin . '/smart-id/callback');

        $session = $this->allkiri->smartIdAuthenticator($this->config->smartId)->startAnonymous(
            self::interactions('Log in to ' . $this->config->serviceName(), 'Log in'),
            initialCallbackUrl: $callbackUrl,
        );
        // The session secret is in here, and it stays on the server: whoever
        // holds it can make links the app accepts.
        $_SESSION['smart-id-qr'] = json_encode($session, JSON_THROW_ON_ERROR);
        unset($_SESSION['smart-id-qr-result']);
        $this->forgetFinished('smart-id-qr');
        $this->audit('authentication started', ['mean' => 'smart-id-device-link', 'session' => $session->sessionId]);

        if ($session->sessionSecret === null) {
            throw new \RuntimeException('Smart-ID started a device-link session without a secret');
        }

        // A Web2App link is built once and is not secret: its authentication
        // code proves the link, and the secret behind it stays here.
        return [
            'started' => true,
            'link' => $session->deviceLink($this->config->smartId->scheme, $this->config->smartId->relyingPartyNameBase64(), DeviceLink::TYPE_WEB2APP)
                ->url($session->sessionSecret),
        ];
    }

    /**
     * The QR code's link as of now.
     *
     * A link carries the seconds since the session started, and the app refuses
     * a stale one, so the page asks for a new link every second. Only the
     * finished link leaves the server, never the secret that signs it.
     *
     * @return array<string, mixed>
     */
    public function smartIdQrLink(): array
    {
        $stored = $_SESSION['smart-id-qr'] ?? null;
        // Nothing here writes to the session, and the page asks every second,
        // so no other call from this browser waits behind this one.
        session_write_close();
        if (!\is_string($stored)) {
            throw new \RuntimeException('No QR sign-in is in progress');
        }
        $session = SmartIdSession::fromJson($stored);
        if ($session->sessionSecret === null) {
            throw new \RuntimeException('The stored QR sign-in has no session secret');
        }

        $link = $session->deviceLink($this->config->smartId->scheme, $this->config->smartId->relyingPartyNameBase64());

        return ['link' => $link->url($session->sessionSecret, $session->elapsedSeconds())];
    }

    /**
     * @return array<string, mixed>
     */
    public function smartIdQrLoginPoll(): array
    {
        // While the code is showing, the page asks for a new link every second.
        // A server that answers one request at a time, as php -S does, would
        // hold those back for as long as SK holds a status request open, and the
        // code on the screen would go stale. So this asks SK for one second at a
        // time, the least it takes.
        return $this->smartIdSignInPoll('smart-id-qr', 'No QR sign-in is in progress', 1_000);
    }

    /**
     * @param int|null $timeoutMs how long SK may hold the status request; the configuration's when null
     *
     * @return array<string, mixed>
     */
    private function smartIdSignInPoll(string $key, string $nothingInProgress, ?int $timeoutMs): array
    {
        return $this->pollWithoutTheLock(
            $key,
            $nothingInProgress,
            function (string $stored) use ($timeoutMs): ?SmartIdSessionStatus {
                $status = $this->allkiri->smartIdClient($this->config->smartId)->sessionStatus(SmartIdSession::fromJson($stored)->sessionId, $timeoutMs);

                // An answer from the app on the same phone is finished by the
                // callback it opens, which carries what proves it. Finished here
                // it would be refused for want of one, and the session gone.
                return $status->isRunning() || self::isSameDevice($status) ? null : $status;
            },
            function (string $stored, SmartIdSessionStatus $status): array {
                $identity = $this->allkiri->smartIdAuthenticator($this->config->smartId)->complete(SmartIdSession::fromJson($stored), $status);

                return ['done' => true] + $this->signedIn($identity, ['flow' => $status->flowType?->value]);
            },
        );
    }

    /**
     * Where the page the person started on learns how an app sign-in ended.
     *
     * The app returns in a new tab, and that tab finishes the sign-in. This one
     * only reads what it left, and never asks SK, so it answers at once: a call
     * still on its way when the new tab replaces the session id is refused, and
     * the shorter the call, the less often that happens.
     *
     * @return array<string, mixed>
     */
    public function smartIdQrLoginState(): array
    {
        $result = $_SESSION['smart-id-qr-result'] ?? null;
        if (\is_array($result)) {
            $answer = [];
            foreach ($result as $name => $value) {
                $answer[(string) $name] = $value;
            }
            if (\is_string($answer['error'] ?? null)) {
                throw new \RuntimeException($answer['error']);
            }

            return $answer;
        }
        if (!\is_string($_SESSION['smart-id-qr'] ?? null)) {
            throw new \RuntimeException('No Smart-ID sign-in is in progress');
        }

        return ['done' => false];
    }

    /**
     * The page the Smart-ID app opens when the person is done on the same
     * phone, with what SK's callback URL rules ask to be checked.
     *
     * The session comes from this browser's own session, never from the URL,
     * which is what ties the returning browser to the one that started. It is
     * forgotten whatever happens next, so a callback works once.
     *
     * @param array<mixed> $query the callback's query, as the app opened it
     *
     * @return array{name: string, identity: string}
     */
    public function smartIdCallback(array $query): array
    {
        $stored = $_SESSION['smart-id-qr'] ?? null;
        unset($_SESSION['smart-id-qr']);
        if (!\is_string($stored)) {
            throw new \RuntimeException(
                'No Smart-ID sign-in is waiting in this browser. If the Smart-ID app opened a different browser than the one you started in, '
                . 'which happens from an app\'s built-in browser, from a browser that is not your default one, and in private mode, '
                . 'start again from your default browser.',
            );
        }

        try {
            $session = SmartIdSession::fromJson($stored);
            $callback = SmartIdCallback::fromQuery($query);
            // Before SK is asked anything: a link that is not this session's
            // own proves nothing.
            $session->verifyCallback($callback);

            // SK may not have the answer ready the moment the app returns.
            $client = $this->allkiri->smartIdClient($this->config->smartId);
            $status = $client->sessionStatus($session->sessionId);
            for ($attempt = 1; $status->isRunning() && $attempt < 3; ++$attempt) {
                $status = $client->sessionStatus($session->sessionId);
            }

            $identity = $this->allkiri->smartIdAuthenticator($this->config->smartId)->complete($session, $status, $callback);
        } catch (\Throwable $error) {
            $_SESSION['smart-id-qr-result'] = ['error' => $error->getMessage()];
            $this->audit('authentication refused', ['mean' => 'smart-id-app', 'reason' => $error->getMessage()]);

            throw $error;
        }

        $answer = ['done' => true] + $this->signedIn($identity, ['flow' => $status->flowType?->value]);
        // For the tab the person started on, in the session as it now is: its
        // state check reads the first, and a QR poll still running the second.
        $_SESSION['smart-id-qr-result'] = $answer;
        $this->rememberFinished('smart-id-qr', $answer);

        return ['name' => $identity->fullName(), 'identity' => $identity->semanticsIdentifier()];
    }

    private static function isSameDevice(SmartIdSessionStatus $status): bool
    {
        return $status->flowType === FlowType::Web2App || $status->flowType === FlowType::App2App;
    }

    // --- signing a file -----------------------------------------------------

    /**
     * Take the uploaded files and put them all in one container, ready to be
     * signed.
     *
     * Uploading again starts a new container. Nothing is ever added to one that
     * exists: each signature covers exactly the files that were in it.
     *
     * @param list<array{name: string, tmp_name: string, error: int}> $files
     *
     * @return array<string, mixed>
     */
    public function upload(array $files): array
    {
        if ($files === []) {
            throw new \RuntimeException('Nothing was uploaded');
        }

        $dataFiles = [];
        $received = [];
        foreach ($files as $file) {
            $name = $file['name'] === '' ? 'document' : basename($file['name']);
            if ($file['error'] !== UPLOAD_ERR_OK || $file['tmp_name'] === '' || !is_uploaded_file($file['tmp_name'])) {
                throw new \RuntimeException(\sprintf(
                    '"%s" did not arrive%s',
                    $name,
                    \in_array($file['error'], [UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE], true) ? ': it is larger than this server accepts' : '',
                ));
            }
            $dataFiles[] = DataFile::fromString($name, (string) file_get_contents($file['tmp_name']));
            $received[] = ['name' => $name, 'size' => filesize($file['tmp_name'])];
        }

        // Refuses two files of the same name, which a container cannot hold.
        $container = AsicContainer::create(...$dataFiles);
        $this->storeContainer($container);
        $this->audit('container created', [
            'files' => $received,
            // What the signatures will actually cover, which is the thing to
            // record before anyone signs anything.
            'fingerprint' => $container->fingerprint(),
        ]);

        return ['files' => $received];
    }

    /**
     * @param array<string, mixed> $request
     *
     * @return array<string, mixed>
     */
    public function mobileIdSignStart(array $request): array
    {
        $signer = $this->allkiri->mobileIdSigner($this->config->mobileId);
        $signing = $signer->start($this->container(), new MobileIdIdentity(
            self::string($request, 'phoneNumber'),
            self::string($request, 'identityCode'),
        ));
        $_SESSION['signing'] = json_encode($signing, JSON_THROW_ON_ERROR);
        $this->forgetFinished('signing');
        $this->audit('signing started', [
            'mean' => 'mobile-id',
            'session' => $signing->session->sessionId,
            'file' => $signing->dataToBeSigned->signatureFileName,
            'covers' => $signing->dataToBeSigned->containerFingerprint,
        ]);

        return ['verificationCode' => $signing->verificationCode()];
    }

    /**
     * @return array<string, mixed>
     */
    public function mobileIdSignPoll(): array
    {
        return $this->pollWithoutTheLock(
            'signing',
            'No signing session is in progress',
            function (string $stored): ?MobileIdSessionStatus {
                $session = MobileIdSigningSession::fromJson($stored)->session;
                $status = $this->allkiri->mobileIdClient($this->config->mobileId)->status($session->type, $session->sessionId);

                return $status->isRunning() ? null : $status;
            },
            function (string $stored, MobileIdSessionStatus $status): array {
                $signer = $this->allkiri->mobileIdSigner($this->config->mobileId);
                $result = $signer->complete($this->container(), MobileIdSigningSession::fromJson($stored), $status);
                $this->storeContainer($result->container);
                $this->auditSigned('mobile-id', $result);

                return ['done' => true, 'level' => $result->level->value];
            },
        );
    }

    /**
     * Start a Smart-ID signature from nothing but the person's identity code.
     *
     * The signature is built around the certificate, and Smart-ID hands one over
     * only for a named account, which a person may have several of. So the
     * person's phone is first asked which account will sign. That costs one
     * interaction, and it means signing does not depend on how, or whether,
     * they signed in.
     *
     * (An application that signs right after a Smart-ID sign-in can skip this
     * step: the sign-in names the account. See docs/smart-id.md.)
     *
     * @param array<string, mixed> $request
     *
     * @return array<string, mixed>
     */
    public function smartIdSignStart(array $request): array
    {
        $person = SemanticsIdentifier::estonian(self::string($request, 'identityCode'));
        // Before the phone is bothered.
        $this->container();

        unset($_SESSION['smart-id-choice'], $_SESSION['signing-smart-id']);
        $this->forgetFinished('smart-id-choice');
        $this->forgetFinished('signing-smart-id');

        $sessionId = $this->allkiri->smartIdSigner($this->smartIdSigning())->chooseCertificate($person);
        // The person goes with it, so the answer can be checked against them.
        $_SESSION['smart-id-choice'] = json_encode(['session' => $sessionId, 'person' => (string) $person], JSON_THROW_ON_ERROR);
        $this->audit('account choice started', ['mean' => 'smart-id', 'session' => $sessionId]);

        return ['started' => true];
    }

    /**
     * Once the person has chosen, ask that account for the signature.
     *
     * The account goes straight into the signing session and is not kept
     * anywhere else.
     *
     * @return array<string, mixed>
     */
    public function smartIdSignChosen(): array
    {
        return $this->pollWithoutTheLock(
            'smart-id-choice',
            'No Smart-ID account choice is in progress',
            function (string $stored): ?SmartIdSessionStatus {
                $status = $this->allkiri->smartIdClient($this->config->smartId)->sessionStatus(self::choice($stored)['session']);

                return $status->isRunning() ? null : $status;
            },
            function (string $stored, SmartIdSessionStatus $status): array {
                $choice = self::choice($stored);
                $signer = $this->allkiri->smartIdSigner($this->smartIdSigning());
                $chosen = $signer->completeCertificateChoice($status);
                // Only this person's devices were asked, so anything else is the
                // service misbehaving, and a signature made with it would be
                // someone else's.
                if ((string) $chosen->documentNumber->semanticsIdentifier() !== $choice['person']) {
                    throw new \RuntimeException('Smart-ID chose an account that belongs to someone other than the person asked');
                }

                $signing = $signer->startNotification(
                    $this->container(),
                    $chosen->documentNumber,
                    self::interactions('Sign the uploaded file'),
                );
                $_SESSION['signing-smart-id'] = json_encode($signing, JSON_THROW_ON_ERROR);
                $this->audit('signing started', [
                    'mean' => 'smart-id',
                    'session' => $signing->session->sessionId,
                    'file' => $signing->dataToBeSigned->signatureFileName,
                    'covers' => $signing->dataToBeSigned->containerFingerprint,
                ]);

                return ['done' => true, 'verificationCode' => $signing->verificationCode()];
            },
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function smartIdSignPoll(): array
    {
        return $this->pollWithoutTheLock(
            'signing-smart-id',
            'No signing session is in progress',
            function (string $stored): ?SmartIdSessionStatus {
                $status = $this->allkiri->smartIdClient($this->config->smartId)->sessionStatus(SmartIdSigningSession::fromJson($stored)->session->sessionId);

                return $status->isRunning() ? null : $status;
            },
            function (string $stored, SmartIdSessionStatus $status): array {
                $signer = $this->allkiri->smartIdSigner($this->smartIdSigning());
                $result = $signer->complete($this->container(), SmartIdSigningSession::fromJson($stored), $status);
                $this->storeContainer($result->container);
                $this->auditSigned('smart-id', $result);

                return ['done' => true, 'level' => $result->level->value];
            },
        );
    }

    /**
     * @param array<string, mixed> $request
     *
     * @return array<string, mixed>
     */
    public function cardSignPrepare(array $request): array
    {
        $algorithms = $request['supportedSignatureAlgorithms'] ?? [];
        if (!\is_array($algorithms)) {
            throw new \RuntimeException('The browser sent no algorithm list');
        }

        $session = $this->allkiri->webEidSigner()->prepare(
            $this->container(),
            self::string($request, 'certificate'),
            array_values($algorithms),
        );
        $_SESSION['signing-card'] = json_encode($session, JSON_THROW_ON_ERROR);
        $this->audit('signing started', [
            'mean' => 'card',
            'file' => $session->dataToBeSigned->signatureFileName,
            'covers' => $session->dataToBeSigned->containerFingerprint,
            'algorithm' => $session->dataToBeSigned->algorithm->value,
        ]);

        return $session->forBrowser();
    }

    /**
     * @param array<string, mixed> $request
     *
     * @return array<string, mixed>
     */
    public function cardSignComplete(array $request): array
    {
        $stored = $_SESSION['signing-card'] ?? null;
        unset($_SESSION['signing-card']);
        if (!\is_string($stored)) {
            throw new \RuntimeException('No signing session is in progress');
        }

        $reported = $request['signatureAlgorithm'] ?? null;
        $result = $this->allkiri->webEidSigner()->complete(
            $this->container(),
            WebEidSigningSession::fromJson($stored),
            self::string($request, 'signature'),
            \is_array($reported) ? CardAlgorithm::fromArray($reported) : null,
        );
        $this->storeContainer($result->container);
        $this->auditSigned('card', $result);

        return ['done' => true, 'level' => $result->level->value];
    }

    /**
     * Lay an archive timestamp over whatever is signed, so it outlasts the
     * algorithms it was made with.
     *
     * @return array<string, mixed>
     */
    public function archive(): array
    {
        $result = $this->allkiri->signingService()->archive($this->container());
        $this->storeContainer($result->container);
        $this->audit('archived', ['file' => $result->signatureFileName, 'level' => $result->level->value]);

        return ['done' => true, 'level' => $result->level->value];
    }

    public function download(): string
    {
        return $this->allkiri->writer()->write($this->container());
    }

    // --- validating ---------------------------------------------------------

    /**
     * @param array{name?: string, tmp_name?: string} $file
     *
     * @return array<string, mixed>
     */
    public function validate(array $file): array
    {
        $path = (string) ($file['tmp_name'] ?? '');
        if ($path === '' || !is_uploaded_file($path)) {
            throw new \RuntimeException('Nothing was uploaded');
        }

        $report = $this->allkiri->validator()->validate(
            (string) file_get_contents($path),
            basename((string) ($file['name'] ?? 'container.asice')),
        );

        $this->audit('validated', [
            'file' => $report->filename,
            'valid' => $report->isValid(),
            'summary' => ReportRenderer::summary($report),
        ]);

        return [
            'valid' => $report->isValid(),
            'summary' => ReportRenderer::summary($report),
            'text' => ReportRenderer::text($report),
            'report' => $report->jsonSerialize(),
        ];
    }

    // --- configuration ------------------------------------------------------

    private static function interactions(string $text, ?string $pinText = null): Interactions
    {
        // The strongest dialogue first: the app shows three codes and only one
        // matches the page. Nothing is cut to fit the PIN dialogue's 60
        // characters, so a longer text needs a shorter one of its own.
        return Interactions::forText($text, $pinText);
    }

    /**
     * QSCD, because that is what a qualified signature requires.
     */
    private function smartIdSigning(): SmartIdConfiguration
    {
        return $this->config->smartId->withCertificateLevel(CertificateLevel::Qscd);
    }

    /**
     * @return array{session: string, person: string}
     */
    private static function choice(string $stored): array
    {
        $choice = json_decode($stored, true, 2, JSON_THROW_ON_ERROR);
        if (!\is_array($choice) || !\is_string($choice['session'] ?? null) || !\is_string($choice['person'] ?? null)) {
            throw new \RuntimeException('The stored Smart-ID account choice is unreadable');
        }

        return ['session' => $choice['session'], 'person' => $choice['person']];
    }

    // --- waiting for a person -----------------------------------------------

    /**
     * Ask whether a person is done, without making the rest of the page wait.
     *
     * PHP locks a browser's session for as long as a request holds it open, and
     * SK keeps a status request open for up to ten seconds, so a poll that kept
     * the session open would queue every other call from that browser behind it.
     * So the stored session is read, the lock released, and SK asked only for the
     * status. While the person has not answered, that is the whole request.
     *
     * Once they have, the lock is taken again, and the session is finished only if
     * it is still the one that was read. Another tab or a double click may have
     * finished it meanwhile, and finishing a signature twice buys two timestamps.
     *
     * A finished answer is given again for a minute to a poll that finds nothing
     * in progress. allkiri.js retries a poll whose answer a gateway lost, and by
     * then the first attempt had already finished the session here.
     *
     * @template TStatus of MobileIdSessionStatus|SmartIdSessionStatus
     *
     * @param \Closure(string): (TStatus|null)                $ask    the stored session's status, or null while it is running
     * @param \Closure(string, TStatus): array<string, mixed> $finish runs with the lock held again
     *
     * @return array<string, mixed>
     */
    private function pollWithoutTheLock(string $key, string $nothingInProgress, \Closure $ask, \Closure $finish): array
    {
        $stored = $_SESSION[$key] ?? null;
        if (!\is_string($stored)) {
            return $this->finishedAnswer($key) ?? throw new \RuntimeException($nothingInProgress);
        }
        $id = session_id();
        session_write_close();

        $status = $ask($stored);
        if ($status === null) {
            return ['done' => false];
        }

        session_start();
        if (session_id() !== $id) {
            // Another request replaced the session meanwhile, as signing in does.
            // Leave the cookie that browser now holds alone.
            header_remove('Set-Cookie');
            session_abort();

            throw new \RuntimeException('This browser\'s session changed while waiting; start again');
        }
        if (($_SESSION[$key] ?? null) !== $stored) {
            return $this->finishedAnswer($key) ?? throw new \RuntimeException('Another request finished this session first');
        }
        unset($_SESSION[$key]);

        $answer = $finish($stored, $status);
        $this->rememberFinished($key, $answer);

        return $answer;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function finishedAnswer(string $key): ?array
    {
        $finished = $_SESSION['finished'] ?? null;
        $entry = \is_array($finished) ? ($finished[$key] ?? null) : null;
        if (!\is_array($entry)) {
            return null;
        }
        $at = $entry['at'] ?? null;
        $remembered = $entry['answer'] ?? null;
        if (!\is_int($at) || !\is_array($remembered) || time() - $at > self::REPEAT_SECONDS) {
            return null;
        }

        $answer = [];
        foreach ($remembered as $name => $value) {
            $answer[(string) $name] = $value;
        }

        return $answer;
    }

    /**
     * @param array<string, mixed> $answer
     */
    private function rememberFinished(string $key, array $answer): void
    {
        $finished = $_SESSION['finished'] ?? null;
        $finished = \is_array($finished) ? $finished : [];
        $finished[$key] = ['answer' => $answer, 'at' => time()];
        $_SESSION['finished'] = $finished;
    }

    private function forgetFinished(string $key): void
    {
        $finished = $_SESSION['finished'] ?? null;
        if (\is_array($finished)) {
            unset($finished[$key]);
            $_SESSION['finished'] = $finished;
        }
    }

    // --- the audit trail ----------------------------------------------------

    /**
     * A finished signature, with the two times that decide whether it stays
     * valid: when the timestamp says it existed, and when its revocation status
     * was checked.
     */
    private function auditSigned(string $mean, \Allkiri\Signing\SigningResult $result): void
    {
        $this->audit('signed', [
            'mean' => $mean,
            'file' => $result->signatureFileName,
            'signature' => $result->signatureId,
            'level' => $result->level->value,
            'timestamp' => $result->timestampTime,
            'revocationChecked' => $result->ocspProducedAt,
            'warnings' => $result->warnings,
        ]);
    }

    /**
     * One line per stage, with a correlation identifier.
     *
     * This is the log that matters, and it is the application's to write: the
     * two-step API makes every stage an explicit call here, so this is the only
     * layer that knows the business meaning of what just happened. The HTTP
     * transcript underneath answers "what did we send"; this answers "who asked
     * for what, and how did it end".
     *
     * `audit` ties the lines of one browser's attempt together, and the eID
     * service's own session identifier ties them to what SK sees, which is what
     * you will be asked for when something is disputed.
     *
     * Personal data is in here on purpose. An audit trail without an identity is
     * not an audit trail. That makes retention, access and deletion your
     * problem, and a demo is not the place to pretend otherwise.
     *
     * @param array<string, mixed> $context
     */
    private function audit(string $event, array $context = []): void
    {
        $this->config->logger->info($event, ['audit' => self::auditId(), 'mode' => $this->config->mode] + $context);
    }

    /**
     * Stable for one browser session, and not the session identifier itself,
     * which is a credential and must not be written anywhere.
     */
    private static function auditId(): string
    {
        $existing = $_SESSION['audit'] ?? null;
        if (\is_string($existing) && $existing !== '') {
            return $existing;
        }
        $fresh = substr(bin2hex(random_bytes(8)), 0, 12);
        $_SESSION['audit'] = $fresh;

        return $fresh;
    }

    // --- the bits a framework would do for you ------------------------------

    /**
     * @param array<string, mixed> $audit more for the audit line, such as the Smart-ID flow that answered
     *
     * @return array<string, mixed>
     */
    private function signedIn(\Allkiri\Auth\AuthenticatedIdentity $identity, array $audit = []): array
    {
        // A new session id for a signed-in session, so an id someone planted or
        // saw before sign-in is worth nothing after it. The page's token and the
        // container's name live in the session, so both carry over.
        session_regenerate_id(true);
        $_SESSION['user'] = $identity->semanticsIdentifier();
        $this->audit('signed in', [
            'identity' => $identity->semanticsIdentifier(),
            'name' => $identity->fullName(),
            // Which certificate it was, so the claim can be checked years later
            // against the revocation data in whatever they went on to sign.
            'serial' => $identity->certificate->serialNumber(),
        ] + $audit);

        return [
            'identity' => $identity->semanticsIdentifier(),
            'name' => $identity->fullName(),
            'country' => $identity->country,
        ];
    }

    private function container(): AsicContainer
    {
        $path = $this->containerPath();
        if (!is_file($path)) {
            throw new \RuntimeException('Upload a file first');
        }

        return $this->allkiri->reader()->read((string) file_get_contents($path));
    }

    private function storeContainer(AsicContainer $container): void
    {
        file_put_contents($this->containerPath(), $this->allkiri->writer()->write($container));
    }

    /**
     * Where this browser's container is kept.
     *
     * Not in the system's temporary directory, where another account on a shared
     * machine could create the folder first and read or replace what goes into
     * it. And not under the session id, which is a credential and changes at
     * sign-in. The folder belongs to this checkout, and the name is random.
     */
    private function containerPath(): string
    {
        $directory = __DIR__ . '/var';
        if (!is_dir($directory) && !mkdir($directory, 0o700, true) && !is_dir($directory)) {
            throw new \RuntimeException('Could not create ' . $directory);
        }

        $name = $_SESSION['container'] ?? null;
        if (!\is_string($name) || preg_match('/^[0-9a-f]{32}$/', $name) !== 1) {
            $name = bin2hex(random_bytes(16));
            $_SESSION['container'] = $name;
        }

        return $directory . '/' . $name . '.asice';
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function string(array $data, string $key): string
    {
        $value = $data[$key] ?? null;
        if (!\is_string($value) || trim($value) === '') {
            throw new \RuntimeException(\sprintf('"%s" is missing', $key));
        }

        return trim($value);
    }
}
