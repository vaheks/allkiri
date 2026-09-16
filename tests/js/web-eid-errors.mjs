/**
 * What a page can tell a person when the ID card fails.
 *
 * web-eid.js rejects with an error carrying one of thirteen ERR_WEBEID_* codes,
 * and its message is written for developers. describeWebEidError() says who can
 * act on each code and gives a sentence for them, while cardLogin() and
 * cardSign() still reject with web-eid.js's own error, for the logs.
 *
 * No dependencies. Stubs global fetch and window.webeid.
 *
 *   node tests/js/web-eid-errors.mjs
 */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const allkiri = require('../../assets/allkiri.js');

let passed = 0;
let failed = 0;

function check(name, condition, detail) {
  if (condition) {
    passed++;
    console.log('ok   ' + name);
  } else {
    failed++;
    console.error('FAIL ' + name + (detail ? ': ' + detail : ''));
  }
}

/** An error shaped as web-eid.js 2.x rejects with. */
function webEidError(code, extra) {
  const error = new Error('web-eid.js says ' + code);
  error.code = code;
  return Object.assign(error, extra || {});
}

async function rejection(promise) {
  try {
    await promise;
    return null;
  } catch (error) {
    return error;
  }
}

// The codes of web-eid.js 2.x (src/errors/ErrorCode.ts at v2.1.0), and who can act on each.
const CODES = {
  ERR_WEBEID_EXTENSION_UNAVAILABLE: 'person',
  ERR_WEBEID_NATIVE_UNAVAILABLE: 'person',
  ERR_WEBEID_VERSION_MISMATCH: 'person',
  ERR_WEBEID_USER_CANCELLED: 'person',
  ERR_WEBEID_USER_TIMEOUT: 'person',
  ERR_WEBEID_NATIVE_FATAL: 'person',
  ERR_WEBEID_CONTEXT_INSECURE: 'operator',
  ERR_WEBEID_NATIVE_INVALID_ARGUMENT: 'developer',
  ERR_WEBEID_ACTION_PENDING: 'developer',
  ERR_WEBEID_MISSING_PARAMETER: 'developer',
  ERR_WEBEID_ACTION_TIMEOUT: 'developer',
  ERR_WEBEID_VERSION_INVALID: 'developer',
  ERR_WEBEID_UNKNOWN_ERROR: 'developer',
};

async function main() {
  check('the helper describes Web eID errors', typeof allkiri.describeWebEidError === 'function');
  if (typeof allkiri.describeWebEidError !== 'function') {
    console.log('\n' + passed + ' passed, ' + (failed) + ' failed');
    process.exit(1);
  }
  const describe = allkiri.describeWebEidError;

  // --- every code ---------------------------------------------------------

  for (const [code, who] of Object.entries(CODES)) {
    const described = describe(webEidError(code));
    check(
      code + ' is for the ' + who,
      described !== null && described.code === code && described.who === who
        && typeof described.text === 'string' && described.text.length > 10,
      JSON.stringify(described),
    );
    check(
      code + '\'s text is not web-eid.js\'s own message',
      described !== null && described.text.indexOf('web-eid.js says') === -1 && described.text.indexOf('ERR_WEBEID') === -1,
    );
  }

  // --- what to update -----------------------------------------------------

  const extension = describe(webEidError('ERR_WEBEID_VERSION_MISMATCH', { requiresUpdate: { extension: true, nativeApp: false } }));
  check(
    'a version mismatch names the extension when only it is out of date',
    extension !== null && /extension/.test(extension.text) && !/application/.test(extension.text),
    extension && extension.text,
  );
  const application = describe(webEidError('ERR_WEBEID_VERSION_MISMATCH', { requiresUpdate: { extension: false, nativeApp: true } }));
  check(
    'and the application when only it is',
    application !== null && /application/.test(application.text) && !/extension/.test(application.text),
    application && application.text,
  );
  const both = describe(webEidError('ERR_WEBEID_VERSION_MISMATCH', { requiresUpdate: { extension: true, nativeApp: true } }));
  check(
    'and both when both are',
    both !== null && /extension/.test(both.text) && /application/.test(both.text),
    both && both.text,
  );

  // --- what is not a Web eID error ----------------------------------------

  check('an unknown ERR_WEBEID_ code is not guessed at', describe(webEidError('ERR_WEBEID_SOMETHING_NEW')) === null);
  check('an error from your server is not a Web eID error', describe(Object.assign(new Error('No challenge was issued'), { status: 400 })) === null);
  check('an error without a code is not one either', describe(new Error('Failed to fetch')) === null);
  check('nor is nothing at all', describe(null) === null && describe(undefined) === null);
  check('nor a code that is not a string', describe({ code: 42 }) === null);

  // --- cardLogin and cardSign keep the original ---------------------------

  globalThis.fetch = () => Promise.resolve({
    ok: true,
    status: 200,
    text: () => Promise.resolve('{"nonce":"bm9uY2Utb2YtdGhpcnR5LXR3by1ieXRlcy1sb25nLi4u"}'),
  });

  const cancelled = webEidError('ERR_WEBEID_USER_CANCELLED');
  globalThis.window = { webeid: { authenticate: () => Promise.reject(cancelled) } };
  const loginFailure = await rejection(allkiri.cardLogin({ challengeUrl: '/api/card/challenge', loginUrl: '/api/card/login' }));
  check('cardLogin rejects with web-eid.js\'s own error', loginFailure === cancelled);
  check('which the page can describe', describe(loginFailure) !== null && describe(loginFailure).who === 'person');

  // --- cardLogin hands web-eid.js what it takes -----------------------------

  // authenticate(challengeNonce, options): the nonce itself. An object holding
  // it reaches the native application unchanged, which reads it as an empty
  // nonce and fails with ERR_WEBEID_NATIVE_FATAL before the card is touched.
  let authenticateArguments = null;
  globalThis.window = {
    webeid: {
      authenticate: (...args) => {
        authenticateArguments = args;
        return Promise.reject(cancelled);
      },
    },
  };
  await rejection(allkiri.cardLogin({ challengeUrl: '/api/card/challenge', loginUrl: '/api/card/login', lang: 'et' }));
  check('cardLogin gives web-eid.js the nonce as a string',
    authenticateArguments !== null && authenticateArguments[0] === 'bm9uY2Utb2YtdGhpcnR5LXR3by1ieXRlcy1sb25nLi4u',
    JSON.stringify(authenticateArguments));
  check('and the language as its options',
    authenticateArguments !== null && authenticateArguments[1] && authenticateArguments[1].lang === 'et',
    JSON.stringify(authenticateArguments));

  const missing = webEidError('ERR_WEBEID_NATIVE_UNAVAILABLE');
  globalThis.window = { webeid: { getSigningCertificate: () => Promise.reject(missing) } };
  const signFailure = await rejection(allkiri.cardSign({ prepareUrl: '/api/card/sign/prepare', completeUrl: '/api/card/sign/complete' }));
  check('cardSign rejects with web-eid.js\'s own error', signFailure === missing);

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
