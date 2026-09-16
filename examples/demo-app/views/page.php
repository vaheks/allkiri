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

<h2>2. Sign a file</h2>

<section>
  <label for="upload">Choose a file to put in a container</label>
  <input type="file" id="upload">
  <button id="upload-go">Upload</button>
  <div class="status" id="upload-status"></div>
</section>

<section>
  <strong>Sign it</strong>
  <p class="note">Signs whatever you uploaded. Each signature is added to the same container.
  Mobile-ID uses the phone number and identity code entered in step 1.</p>
  <label for="sign-sid-code">Smart-ID identity code</label>
  <input type="text" id="sign-sid-code" value="<?= $prefill('50001029996') ?>">
  <button id="sign-card">With an ID card</button>
  <button id="sign-mid">With Mobile-ID</button>
  <button id="sign-sid">With Smart-ID</button>
  <div class="code" id="sign-code"></div>
  <div class="status" id="sign-status"></div>
  <button id="archive">Add an archive timestamp</button>
  <button id="download">Download the container</button>
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

  // --- signing a file ----------------------------------------------------

  $('upload-go').onclick = function () {
    var file = $('upload').files[0];
    if (!file) { say('upload-status', 'Choose a file first', true); return; }
    var form = new FormData();
    form.append('file', file);
    fetch('/api/upload', { method: 'POST', headers: { 'X-CSRF-Token': csrfToken }, body: form })
      .then(function (r) { return r.json(); })
      .then(function (answer) {
        if (answer.error) { throw new Error(answer.error); }
        say('upload-status', 'Ready to sign: ' + answer.name + ' (' + answer.size + ' bytes)');
      })
      .catch(failed('upload-status'));
  };

  function signed(result) {
    say('sign-status', 'Signed. The container is now ' + result.level + '.');
    $('sign-code').textContent = '';
  }

  $('sign-card').onclick = function () {
    say('sign-status', 'Insert the card…');
    allkiri.cardSign({ prepareUrl: '/api/card/sign/prepare', completeUrl: '/api/card/sign/complete' })
      .then(signed).catch(cardFailed('sign-status'));
  };

  $('sign-mid').onclick = function () {
    say('sign-status', 'Sending to the phone…');
    allkiri.notificationFlow({
      startUrl: '/api/mobile-id/sign/start',
      pollUrl: '/api/mobile-id/sign/poll',
      body: { phoneNumber: $('mid-phone').value, identityCode: $('mid-code').value },
      onCode: function (code) {
        allkiri.showVerificationCode($('sign-code'), code);
        say('sign-status', 'Check this code, then enter PIN 2.');
      }
    }).then(signed).catch(failed('sign-status'));
  };

  // Two requests to the phone. Smart-ID signs with one account, not a person,
  // so the app is first asked which account will sign. Once it has answered,
  // the server asks that account for the signature and returns its code.
  $('sign-sid').onclick = function () {
    $('sign-code').textContent = '';
    say('sign-status', 'Sending to the app…');
    allkiri.post('/api/smart-id/sign/start', { identityCode: $('sign-sid-code').value })
      .then(function () {
        say('sign-status', 'Answer the request in the Smart-ID app. It tells this page which of your accounts will sign.');
        return allkiri.poll('/api/smart-id/sign/chosen');
      })
      .then(function (chosen) {
        allkiri.showVerificationCode($('sign-code'), chosen.verificationCode);
        say('sign-status', 'Pick this code in the Smart-ID app.');
        return allkiri.poll('/api/smart-id/sign/poll');
      })
      .then(signed).catch(failed('sign-status'));
  };

  $('archive').onclick = function () {
    say('sign-status', 'Timestamping…');
    allkiri.post('/api/archive')
      .then(function (r) { say('sign-status', 'Archived. The container is now ' + r.level + '.'); })
      .catch(failed('sign-status'));
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
