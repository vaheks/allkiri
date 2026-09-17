<?php
/**
 * The page. Everything it needs from the server is $config, so that a live-mode
 * page cannot look like a demo-mode one, and the token it sends back.
 *
 * @var \Allkiri\Demo\Config $config
 * @var string               $csrfToken every call that changes something carries it back
 */
$live = $config->isLive();
// In live mode nothing is prefilled: the published test numbers belong to
// nobody, and a live service would refuse them anyway. Worse, a prefilled real
// number is a request sent to a stranger's phone.
$prefill = static fn(string $value): string => $live ? '' : $value;
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="<?= htmlspecialchars($csrfToken, ENT_QUOTES) ?>">
<title>allkiri demo</title>
<style>
  :root { color-scheme: light dark; --line: #8884; --ink: inherit; }
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 46rem; margin: 2rem auto; padding: 0 1rem; }
  h1 { font-size: 1.4rem; }
  h2 { font-size: 1.1rem; margin-top: 2.5rem; }
  section { border: 1px solid var(--line); border-radius: 8px; padding: 1rem 1.2rem; margin: 1rem 0; }
  label { display: block; margin: .6rem 0 .2rem; font-size: .9rem; }
  input[type=text], input[type=file] { width: 100%; padding: .45rem; box-sizing: border-box; }
  button { padding: .5rem 1rem; margin-top: .8rem; margin-right: .4rem; cursor: pointer; }
  .code { font-size: 2.2rem; letter-spacing: .2em; font-variant-numeric: tabular-nums; margin: .5rem 0; }
  .note { font-size: .85rem; opacity: .75; }
  .banner { font-size: .9rem; border: 1px solid var(--line); border-left-width: 5px; border-radius: 6px; padding: .7rem .9rem; }
  .banner.demo { border-left-color: #2a7; }
  .banner.live { border-left-color: #c00; background: #c0011; }
  .status { margin-top: .8rem; min-height: 1.5rem; }
  .status.bad { color: #c00; }
  pre { background: #8881; padding: .8rem; overflow-x: auto; font-size: .8rem; }
  #qr svg { max-width: 15rem; height: auto; }
</style>
</head>
<body>

<h1>allkiri demo</h1>

<?php if ($live) { ?>
<p class="banner live">
  <strong>Live services.</strong>
  Relying party <code><?= htmlspecialchars($config->relyingPartyName(), ENT_QUOTES) ?></code>.
  Every signature made here is a real signature by a real person, timestamps are
  billed, and requests go to real phones. Nothing on this page is a test.
</p>
<?php } else { ?>
<p class="banner demo">
  <strong>Test services.</strong>
  Nothing made here is a valid signature. Use the credentials SK publishes:
  Mobile-ID <code>+37200000766</code> / <code>60001019906</code>,
  Smart-ID <code>50001029996</code>,
  or a test ID card.
</p>
<?php } ?>

<h2>1. Sign in</h2>

<section>
  <strong>ID card</strong>
  <p class="note">Needs the Web eID extension, its native application, and an HTTPS origin.</p>
  <button id="card-login">Sign in with an ID card</button>
  <div class="status" id="card-login-status"></div>
</section>

<section>
  <strong>Mobile-ID</strong>
  <label for="mid-phone">Phone number</label>
  <input type="text" id="mid-phone" value="<?= $prefill('+37200000766') ?>">
  <label for="mid-code">Identity code</label>
  <input type="text" id="mid-code" value="<?= $prefill('60001019906') ?>">
  <button id="mid-login">Sign in with Mobile-ID</button>
  <div class="code" id="mid-login-code"></div>
  <div class="status" id="mid-login-status"></div>
</section>

<section>
  <strong>Smart-ID</strong>
  <label for="sid-code">Identity code</label>
  <input type="text" id="sid-code" value="<?= $prefill('50001029996') ?>">
  <button id="sid-login">Sign in with Smart-ID</button>
  <div class="code" id="sid-login-code"></div>
  <div class="status" id="sid-login-status"></div>
</section>

<?php $demoApp = $live ? '' : ' (the Smart-ID demo app, with a demo account)'; ?>
<section id="sid-device">
  <strong>Smart-ID without an identity code</strong>
  <p class="note" data-device="computer">Scan the code with the Smart-ID app on your phone<?= $demoApp ?>. The code changes every second.</p>
  <p class="note" data-device="phone" hidden>Opens the Smart-ID app on this phone<?= $demoApp ?>, which brings you back in a new tab. To use Smart-ID on another device, show a QR code instead.</p>
  <button id="sid-app-login" hidden>Open the Smart-ID app</button>
  <button id="sid-qr-login">Show a QR code</button>
  <button id="sid-qr-stop" hidden>Stop</button>
  <p id="sid-app-again" hidden><a id="sid-app-link" href="#">Open the Smart-ID app</a> if it did not open by itself.</p>
  <div id="qr"></div>
  <div class="status" id="sid-qr-status"></div>
</section>

<h2>2. Sign a file</h2>

<p class="note">Upload one or more files, then sign them with any of the three, as often as you like.
Each signature covers all the files and is added to the same container. Signing uses nothing from step 1.</p>

<section>
  <label for="upload">Choose the files to put in a container</label>
  <input type="file" id="upload" multiple>
  <p class="note">Uploading again starts a new container. Files cannot be added to one that is already signed.</p>
  <button id="upload-go">Upload</button>
  <div class="status" id="upload-status"></div>
</section>

<section>
  <strong>ID card</strong>
  <p class="note">Reads the signing certificate from the card, then asks for PIN 2.</p>
  <button id="card-sign">Sign with an ID card</button>
  <div class="status" id="card-sign-status"></div>
</section>

<section>
  <strong>Mobile-ID</strong>
  <label for="mid-sign-phone">Phone number</label>
  <input type="text" id="mid-sign-phone" value="<?= $prefill('+37200000766') ?>">
  <label for="mid-sign-identity">Identity code</label>
  <input type="text" id="mid-sign-identity" value="<?= $prefill('60001019906') ?>">
  <button id="mid-sign">Sign with Mobile-ID</button>
  <div class="code" id="mid-sign-code"></div>
  <div class="status" id="mid-sign-status"></div>
</section>

<section>
  <strong>Smart-ID</strong>
  <p class="note">Two prompts: the app first asks which of your accounts will sign, then for PIN 2.</p>
  <label for="sid-sign-identity">Identity code</label>
  <input type="text" id="sid-sign-identity" value="<?= $prefill('50001029996') ?>">
  <button id="sid-sign">Sign with Smart-ID</button>
  <div class="code" id="sid-sign-code"></div>
  <div class="status" id="sid-sign-status"></div>
</section>

<section>
  <strong>Container</strong>
  <p class="note">Holds the files and every signature above. An archive timestamp covers all of them.</p>
  <button id="archive">Add an archive timestamp</button>
  <button id="download">Download the container</button>
  <div class="status" id="container-status"></div>
</section>

<h2>3. Validate</h2>

<section>
  <label for="check">Choose a signed container</label>
  <input type="file" id="check">
  <button id="check-go">Validate</button>
  <div class="status" id="check-status"></div>
  <pre id="check-report" hidden></pre>
</section>

<script src="/vendor/web-eid.js" integrity="sha384-eNqE5qChFP5o6ucg8NHzHOkGCd1MavcHSKU2gSR/Dp8eDOf3d9GBlayz3btZ15hB"></script>
<script src="/allkiri-qr.js"></script>
<script src="/allkiri.js"></script>
<script>
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };

  // The server refuses any call that changes something unless it carries this
  // token. allkiri.js adds it to every call it makes; the two uploads below add
  // it themselves.
  var csrfToken = document.querySelector('meta[name="csrf-token"]').content;
  allkiri.configure({ csrfToken: csrfToken });

  function say(id, message, bad) {
    var el = $(id);
    el.textContent = message;
    el.classList.toggle('bad', !!bad);
  }

  function failed(id) {
    return function (error) {
      say(id, error && error.message ? error.message : String(error), true);
    };
  }

  // web-eid.js's own messages are written for developers. The person gets a
  // sentence they can act on, and the error itself goes to the console.
  function cardFailed(id) {
    return function (error) {
      var problem = allkiri.describeWebEidError(error);
      if (!problem) {
        failed(id)(error);
        return;
      }
      if (window.console) {
        window.console.warn(problem.code, error);
      }
      say(id, problem.text, true);
    };
  }

  // --- signing in --------------------------------------------------------

  $('card-login').onclick = function () {
    say('card-login-status', 'Insert the card and follow the prompts…');
    allkiri.cardLogin({ challengeUrl: '/api/card/challenge', loginUrl: '/api/card/login' })
      .then(function (user) { say('card-login-status', 'Signed in as ' + user.name + ' (' + user.identity + ')'); })
      .catch(cardFailed('card-login-status'));
  };

  $('mid-login').onclick = function () {
    say('mid-login-status', 'Sending to the phone…');
    $('mid-login-code').textContent = '';
    allkiri.notificationFlow({
      startUrl: '/api/mobile-id/login/start',
      pollUrl: '/api/mobile-id/login/poll',
      body: { phoneNumber: $('mid-phone').value, identityCode: $('mid-code').value },
      onCode: function (code) {
        allkiri.showVerificationCode($('mid-login-code'), code);
        say('mid-login-status', 'Check this code matches the one on the phone, then enter PIN 1.');
      }
    }).then(function (user) { say('mid-login-status', 'Signed in as ' + user.name + ' (' + user.identity + ')'); })
      .catch(failed('mid-login-status'));
  };

  $('sid-login').onclick = function () {
    say('sid-login-status', 'Sending to the app…');
    $('sid-login-code').textContent = '';
    allkiri.notificationFlow({
      startUrl: '/api/smart-id/login/start',
      pollUrl: '/api/smart-id/login/poll',
      body: { identityCode: $('sid-code').value },
      onCode: function (code) {
        allkiri.showVerificationCode($('sid-login-code'), code);
        say('sid-login-status', 'Pick this code in the Smart-ID app.');
      }
    }).then(function (user) { say('sid-login-status', 'Signed in as ' + user.name + ' (' + user.identity + ')'); })
      .catch(failed('sid-login-status'));
  };

  // --- Smart-ID without an identity code ----------------------------------
  //
  // SK's guidance: on a phone or a tablet, open the Smart-ID app on the same
  // device first and offer a QR code for another device second; on a computer,
  // the QR code alone. ?device=phone or ?device=computer overrides the guess.
  //
  // Either way the server starts a session that names nobody and keeps its
  // secret. For a QR code it mints a fresh link every second. For the app it
  // starts the session with a callback URL and hands over one link, and the
  // app brings the person back to /smart-id/callback in a new tab, which
  // finishes the sign-in. This tab then only watches for the result. One
  // session serves both, so a QR code shown after the app keeps it.
  //
  // A new attempt, or Stop, ends the one before on the page, and the one it
  // ended still settles a moment later, as cancelled. Only the latest attempt
  // writes to the block.
  var forcedDevice = /[?&]device=(phone|computer)(&|$)/.exec(window.location.search);
  var onPhone = forcedDevice ? forcedDevice[1] === 'phone' : !!(
    (navigator.userAgentData && navigator.userAgentData.mobile)
    || /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent)
    || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1)
  );
  document.querySelectorAll('#sid-device [data-device]').forEach(function (el) {
    el.hidden = el.getAttribute('data-device') !== (onPhone ? 'phone' : 'computer');
  });
  if (onPhone) {
    $('sid-app-login').hidden = false;
    $('sid-qr-login').textContent = 'Show a QR code for another device';
  }

  var device = { attempt: 0, active: false, appLink: null, qr: null, wait: null };

  function deviceClear() {
    if (device.qr) { device.qr.stop(); device.qr = null; }
    if (device.wait) { device.wait.abort(); device.wait = null; }
    $('qr').innerHTML = '';
    $('sid-qr-stop').hidden = true;
    $('sid-app-again').hidden = true;
  }

  // Returns whether the attempt it starts is still the latest.
  function deviceBegin() {
    var attempt = ++device.attempt;
    deviceClear();
    device.active = true;
    return function () { return attempt === device.attempt; };
  }

  function deviceEnd() {
    device.active = false;
    device.appLink = null;
    deviceClear();
  }

  function deviceSignedIn(current, elsewhere) {
    return function (user) {
      if (!current() || !user) { return; }
      deviceEnd();
      say('sid-qr-status', 'Signed in as ' + user.name + ' (' + user.identity + ')'
        + (elsewhere ? ', in the tab the Smart-ID app opened.' : ''));
    };
  }

  // Before giving up, ask how the sign-in ended: the tab the app opened may
  // have finished it. Signing in there replaces the session id, and a call
  // this tab sent just before is refused for it, although nothing failed.
  function deviceFailed(current) {
    return function (error) {
      if (!current()) { return; }
      var fail = function () {
        if (!current()) { return; }
        deviceEnd();
        failed('sid-qr-status')(error);
      };
      allkiri.post('/api/smart-id/login/qr/state').then(function (state) {
        if (state && state.done) {
          deviceSignedIn(current, true)(state);
        } else {
          fail();
        }
      }, fail);
    };
  }

  $('sid-app-login').onclick = function () {
    var link = device.active ? device.appLink : null;
    var current = deviceBegin();
    var started = link ? Promise.resolve({ link: link }) : allkiri.post('/api/smart-id/login/qr/start', { sameDevice: true });
    if (!link) { say('sid-qr-status', 'Starting…'); }

    started.then(function (answer) {
      if (!current() || !answer) { return null; }
      device.appLink = answer.link;
      $('sid-app-link').href = answer.link;
      $('sid-app-again').hidden = false;
      $('sid-qr-stop').hidden = false;
      say('sid-qr-status', 'Continue in the Smart-ID app. It brings you back in a new tab.');
      // Some browsers hand a link to an app only straight from a tap, which is
      // why the same link also stays on the page.
      window.location.href = answer.link;
      device.wait = new AbortController();
      return allkiri.poll('/api/smart-id/login/qr/state', { interval: 1500, timeout: 600000, signal: device.wait.signal });
    }).then(deviceSignedIn(current, true), deviceFailed(current));
  };

  $('sid-qr-login').onclick = function () {
    var reuse = device.active && device.appLink !== null;
    var current = deviceBegin();
    if (!reuse) { device.appLink = null; }
    var started = reuse ? Promise.resolve(true) : allkiri.post('/api/smart-id/login/qr/start', { sameDevice: false });
    say('sid-qr-status', reuse ? 'Scan the code with the Smart-ID app, then enter PIN 1.' : 'Starting…');

    started.then(function () {
      if (!current()) { return null; }
      say('sid-qr-status', 'Scan the code with the Smart-ID app, then enter PIN 1.');
      device.qr = allkiri.deviceLinkQr({
        linkUrl: '/api/smart-id/login/qr/link',
        pollUrl: '/api/smart-id/login/qr/poll',
        element: $('qr'),
        size: 240,
        onError: function (error) { if (current()) { failed('sid-qr-status')(error); } }
      });
      $('sid-qr-stop').hidden = false;
      return device.qr.promise;
    }).then(deviceSignedIn(current, false), deviceFailed(current));
  };

  $('sid-qr-stop').onclick = function () {
    if (!device.active) { return; }
    device.attempt++;
    deviceEnd();
    say('sid-qr-status', 'Stopped.');
  };

  // --- signing a file ----------------------------------------------------

  $('upload-go').onclick = function () {
    var files = $('upload').files;
    if (!files.length) { say('upload-status', 'Choose one or more files first', true); return; }
    var form = new FormData();
    for (var i = 0; i < files.length; i++) {
      form.append('files[]', files[i]);
    }
    fetch('/api/upload', { method: 'POST', headers: { 'X-CSRF-Token': csrfToken }, body: form })
      .then(function (r) { return r.json(); })
      .then(function (answer) {
        if (answer.error) { throw new Error(answer.error); }
        say('upload-status', 'Ready to sign: ' + answer.files.map(function (f) {
          return f.name + ' (' + f.size + ' bytes)';
        }).join(', '));
      })
      .catch(failed('upload-status'));
  };

  // Each means reports in its own block. The container they add to is the same.
  function signed(statusId, codeId) {
    return function (result) {
      if (codeId) { $(codeId).textContent = ''; }
      say(statusId, 'Signed. The container is now ' + result.level + '.');
    };
  }

  $('card-sign').onclick = function () {
    say('card-sign-status', 'Insert the card…');
    allkiri.cardSign({ prepareUrl: '/api/card/sign/prepare', completeUrl: '/api/card/sign/complete' })
      .then(signed('card-sign-status')).catch(cardFailed('card-sign-status'));
  };

  $('mid-sign').onclick = function () {
    say('mid-sign-status', 'Sending to the phone…');
    $('mid-sign-code').textContent = '';
    allkiri.notificationFlow({
      startUrl: '/api/mobile-id/sign/start',
      pollUrl: '/api/mobile-id/sign/poll',
      body: { phoneNumber: $('mid-sign-phone').value, identityCode: $('mid-sign-identity').value },
      onCode: function (code) {
        allkiri.showVerificationCode($('mid-sign-code'), code);
        say('mid-sign-status', 'Check this code, then enter PIN 2.');
      }
    }).then(signed('mid-sign-status', 'mid-sign-code')).catch(failed('mid-sign-status'));
  };

  // Two requests to the phone. Smart-ID signs with one account, not a person,
  // so the app is first asked which account will sign. Once it has answered,
  // the server asks that account for the signature and returns its code.
  $('sid-sign').onclick = function () {
    say('sid-sign-status', 'Sending to the app…');
    $('sid-sign-code').textContent = '';
    allkiri.post('/api/smart-id/sign/start', { identityCode: $('sid-sign-identity').value })
      .then(function () {
        say('sid-sign-status', 'Answer the request in the Smart-ID app. It tells this page which of your accounts will sign.');
        return allkiri.poll('/api/smart-id/sign/chosen');
      })
      .then(function (chosen) {
        allkiri.showVerificationCode($('sid-sign-code'), chosen.verificationCode);
        say('sid-sign-status', 'Pick this code in the Smart-ID app, then enter PIN 2.');
        return allkiri.poll('/api/smart-id/sign/poll');
      })
      .then(signed('sid-sign-status', 'sid-sign-code')).catch(failed('sid-sign-status'));
  };

  $('archive').onclick = function () {
    say('container-status', 'Timestamping…');
    allkiri.post('/api/archive')
      .then(function (r) { say('container-status', 'Archived. The container is now ' + r.level + '.'); })
      .catch(failed('container-status'));
  };

  $('download').onclick = function () { window.location = '/api/download'; };

  // --- validating --------------------------------------------------------

  $('check-go').onclick = function () {
    var file = $('check').files[0];
    if (!file) { say('check-status', 'Choose a container first', true); return; }
    var form = new FormData();
    form.append('file', file);
    $('check-report').hidden = true;
    fetch('/api/validate', { method: 'POST', headers: { 'X-CSRF-Token': csrfToken }, body: form })
      .then(function (r) { return r.json(); })
      .then(function (answer) {
        if (answer.error) { throw new Error(answer.error); }
        say('check-status', answer.summary, !answer.valid);
        $('check-report').textContent = answer.text;
        $('check-report').hidden = false;
      })
      .catch(failed('check-status'));
  };
}());
</script>

</body>
</html>
