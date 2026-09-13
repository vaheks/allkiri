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
 * back instead.
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

/** Answer each request from the list in turn, so a poll loop can be watched. */
function answeringInTurn(answers) {
  let index = 0;
  const seen = [];
  globalThis.fetch = () => {
    const answer = answers[Math.min(index, answers.length - 1)];
    index++;
    seen.push(answer);
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

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
