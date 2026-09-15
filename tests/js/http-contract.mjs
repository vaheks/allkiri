/**
 * What the browser helper does with answers it cannot use.
 *
 * These exist because of a real failure. A misconfigured log path made PHP
 * print a warning ahead of the JSON, the helper read the unparseable body as an
 * empty answer, and the polling loop took that for "not finished yet". It went
 * on asking until the session it was waiting for had been finished and consumed,
 * and then reported that no session was in progress. The authentication had
 * actually succeeded.
 *
 * So: an answer that cannot be read is an error, immediately, and says what came
 * back instead. Only a poll that got no answer from the server at all, or a
 * gateway's 502, 503 or 504, is asked again.
 *
 * No dependencies. Stubs global fetch.
 *
 *   node tests/js/http-contract.mjs
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

/** Answer every request with the same status, body and content type. */
function answering(status, body) {
  globalThis.fetch = () => Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(body),
  });
}

/**
 * Answer each request from the list in turn, so a poll loop can be watched. A
 * null in the list makes fetch itself fail, as it does when no answer arrives.
 */
function answeringInTurn(answers) {
  let index = 0;
  globalThis.fetch = () => {
    const answer = answers[Math.min(index, answers.length - 1)];
    index++;
    if (answer === null) {
      return Promise.reject(new TypeError('Failed to fetch'));
    }
    return Promise.resolve({
      ok: answer.status >= 200 && answer.status < 300,
      status: answer.status,
      text: () => Promise.resolve(answer.body),
    });
  };
  return () => index;
}

async function rejects(promise) {
  try {
    await promise;
    return null;
  } catch (error) {
    return error;
  }
}

async function settle(promise) {
  try {
    return { value: await promise, error: null };
  } catch (error) {
    return { value: null, error };
  }
}

async function main() {
  // --- post -------------------------------------------------------------

  answering(200, '{"done":true,"name":"MARY ÄNN"}');
  const good = await allkiri.post('/api/x');
  check('a JSON answer is returned as an object', good && good.name === 'MARY ÄNN');

  // The exact shape of the failure that started this: PHP's warning, then the
  // JSON it was supposed to be.
  const warning = '<br />\n<b>Warning</b>: file_put_contents(C:/nope/x.log): Failed to open stream'
    + ' in <b>logger.php</b> on line <b>45</b><br />\n{"done":true}';
  answering(200, warning);
  const unreadable = await rejects(allkiri.post('/api/x'));
  check('a 200 that is not JSON is an error', unreadable !== null);
  check(
    'the error says what came back instead',
    unreadable !== null && /not with JSON/.test(unreadable.message) && /Warning/.test(unreadable.message),
    unreadable && unreadable.message,
  );
  check('the error carries the status', unreadable !== null && unreadable.status === 200);
  check('the error carries the whole body', unreadable !== null && unreadable.body === warning);
  check(
    'the excerpt is one short line',
    unreadable !== null && !/\n/.test(unreadable.message) && unreadable.message.length < 200,
    unreadable && String(unreadable.message.length),
  );

  answering(400, '{"error":"No Mobile-ID session is in progress"}');
  const refused = await rejects(allkiri.post('/api/x'));
  check(
    'a refusal keeps the server\'s own wording',
    refused !== null && refused.message === 'No Mobile-ID session is in progress',
    refused && refused.message,
  );

  answering(500, '<html><body>Internal Server Error</body></html>');
  const html = await rejects(allkiri.post('/api/x'));
  check('an HTML error page is still an error', html !== null && html.status === 500);

  answering(200, '');
  const empty = await allkiri.post('/api/x');
  check('an empty answer is null rather than an error', empty === null);

  // --- poll -------------------------------------------------------------

  const count = answeringInTurn([
    { status: 200, body: '{"done":false}' },
    { status: 200, body: '{"done":true,"name":"MARY ÄNN"}' },
  ]);
  const finished = await allkiri.poll('/api/poll', { interval: 1 });
  check('polling stops when the server says done', finished && finished.name === 'MARY ÄNN');
  check('it asked exactly twice', count() === 2, String(count()));

  // The bug: an unreadable answer must not be read as "not finished yet".
  const spins = answeringInTurn([{ status: 200, body: 'not json at all' }]);
  const stopped = await rejects(allkiri.poll('/api/poll', { interval: 1, timeout: 5000 }));
  check('polling stops on an unreadable answer', stopped !== null);
  check('it did not keep asking', spins() === 1, String(spins()));

  // An empty answer is not an answer either, once you are waiting for one.
  const empties = answeringInTurn([{ status: 200, body: '' }]);
  const refusedEmpty = await rejects(allkiri.poll('/api/poll', { interval: 1, timeout: 5000 }));
  check('polling stops on an empty answer', refusedEmpty !== null);
  check('it did not keep asking either', empties() === 1, String(empties()));

  const laters = answeringInTurn([
    { status: 200, body: '{"done":false}' },
    { status: 200, body: '{"done":false}' },
    { status: 400, body: '{"error":"No Mobile-ID session is in progress"}' },
  ]);
  const gone = await rejects(allkiri.poll('/api/poll', { interval: 1 }));
  check(
    'a refusal mid-poll is reported as the server worded it',
    gone !== null && gone.message === 'No Mobile-ID session is in progress',
    gone && gone.message,
  );
  check('after three questions', laters() === 3, String(laters()));

  // --- poll: what is asked again ------------------------------------------

  const dropped = answeringInTurn([null, { status: 200, body: '{"done":true,"name":"MARY ÄNN"}' }]);
  const afterDrop = await settle(allkiri.poll('/api/poll', { interval: 1, timeout: 5000 }));
  check(
    'a poll that got no answer at all is asked again',
    afterDrop.value !== null && afterDrop.value.name === 'MARY ÄNN' && dropped() === 2,
    afterDrop.error ? afterDrop.error.message : String(dropped()),
  );

  for (const status of [502, 503, 504]) {
    const gateway = answeringInTurn([
      { status, body: '<html><body>Bad Gateway</body></html>' },
      { status: 200, body: '{"done":true}' },
    ]);
    const recovered = await settle(allkiri.poll('/api/poll', { interval: 1, timeout: 5000 }));
    check(
      'a ' + status + ' from a gateway is asked again',
      recovered.value !== null && recovered.value.done === true && gateway() === 2,
      recovered.error ? recovered.error.message : String(gateway()),
    );
  }

  for (const [what, answer] of [
    ['a 500 from the server', { status: 500, body: '{"error":"Something broke"}' }],
    ['a 400 from the server', { status: 400, body: '{"error":"No Mobile-ID session is in progress"}' }],
    ['an unreadable 200', { status: 200, body: '<br /><b>Warning</b>' }],
  ]) {
    const once = answeringInTurn([answer, { status: 200, body: '{"done":true}' }]);
    const outcome = await settle(allkiri.poll('/api/poll', { interval: 1, timeout: 5000 }));
    check(what + ' still ends the wait at once', outcome.error !== null && once() === 1, String(once()));
  }

  const forever = answeringInTurn([{ status: 503, body: 'Service Unavailable' }]);
  const exhausted = await settle(allkiri.poll('/api/poll', { interval: 5, timeout: 150 }));
  check(
    'asking again stops at the timeout, with the last error',
    exhausted.error !== null && exhausted.error.status === 503,
    exhausted.error ? exhausted.error.message : 'resolved',
  );
  check(
    'that error says how many times it asked again',
    exhausted.error !== null && exhausted.error.retries >= 1 && forever() === exhausted.error.retries + 1,
    forever() + ' requests, retries ' + (exhausted.error && exhausted.error.retries),
  );
  check('and it backed off rather than hammering', forever() <= 8, String(forever()));

  // The same, however slow the machine: the only failure arrives after the
  // deadline, and still says how many times the poll had asked again.
  let lateRequests = 0;
  globalThis.fetch = () => {
    lateRequests++;
    return new Promise((resolve) => setTimeout(() => resolve({
      ok: false,
      status: 503,
      text: () => Promise.resolve('Service Unavailable'),
    }), 60));
  };
  const late = await settle(allkiri.poll('/api/poll', { interval: 5, timeout: 20 }));
  check(
    'a failure that arrives after the deadline still carries retries',
    late.error !== null && late.error.status === 503 && late.error.retries === 0 && lateRequests === 1,
    (late.error ? 'retries ' + late.error.retries : 'resolved') + ', ' + lateRequests + ' requests',
  );

  answeringInTurn([null]);
  const controller = new AbortController();
  const startedAt = Date.now();
  const cancelled = settle(allkiri.poll('/api/poll', { interval: 1000, timeout: 10000, signal: controller.signal }));
  setTimeout(() => controller.abort(), 50);
  const abortOutcome = await cancelled;
  check(
    'an abort during a backoff ends the wait at once',
    abortOutcome.error !== null && abortOutcome.error.name === 'AbortError' && Date.now() - startedAt < 500,
    (abortOutcome.error ? abortOutcome.error.name : 'resolved') + ' after ' + (Date.now() - startedAt) + ' ms',
  );

  const ticks = answeringInTurn([{ status: 200, body: '{"done":false}' }, { status: 200, body: '{"done":true}' }]);
  const brokenTick = await settle(allkiri.poll('/api/poll', {
    interval: 1,
    timeout: 5000,
    onTick: () => { throw new TypeError('the page broke'); },
  }));
  check(
    'an error in onTick is not mistaken for a network failure',
    brokenTick.error instanceof TypeError && ticks() === 1,
    (brokenTick.error ? brokenTick.error.message : 'resolved') + ', ' + ticks() + ' requests',
  );

  const listeners = { added: 0, removed: 0 };
  const quietSignal = {
    aborted: false,
    addEventListener: () => { listeners.added++; },
    removeEventListener: () => { listeners.removed++; },
  };
  answeringInTurn([
    { status: 200, body: '{"done":false}' },
    { status: 200, body: '{"done":false}' },
    { status: 200, body: '{"done":true}' },
  ]);
  await allkiri.poll('/api/poll', { interval: 1, signal: quietSignal });
  check(
    'a wait that finished leaves no abort listeners behind',
    listeners.added === 2 && listeners.removed === 2,
    JSON.stringify(listeners),
  );

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
