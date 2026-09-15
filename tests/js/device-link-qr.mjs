/**
 * The Smart-ID QR loop.
 *
 * A device-link QR needs a new link from the server about once a second. The
 * loop must not pile requests onto a slow server, must cancel what it started
 * when it stops, and must honour a signal the page gave it: before, a slow
 * server got a new request every second whether or not the last had answered,
 * stop() could not cancel any of them, and a caller's abort stopped nothing.
 *
 * No dependencies. Stubs global fetch; the QR encoder is the real one.
 *
 *   node tests/js/device-link-qr.mjs
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

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function abortError() {
  const error = new Error('The operation was aborted');
  error.name = 'AbortError';
  return error;
}

function respond(status, body) {
  return { ok: status >= 200 && status < 300, status, text: () => Promise.resolve(body) };
}

/** Settles within the given time, or reports that it did not. */
async function settleWithin(promise, ms) {
  let timer;
  const late = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ late: true, value: null, error: null }), ms);
  });
  const outcome = promise.then(
    (value) => ({ late: false, value, error: null }),
    (error) => ({ late: false, value: null, error }),
  );
  const result = await Promise.race([outcome, late]);
  clearTimeout(timer);
  return result;
}

/**
 * A server whose link endpoint answers after linkDelay ms, as fetch does: at
 * once with an AbortError when the request's signal is aborted. Its poll
 * endpoint says "not done" until finish() is called.
 */
function server(linkDelay) {
  const state = { inFlight: 0, maxInFlight: 0, links: 0, polls: 0, done: false, signals: [] };
  state.finish = () => { state.done = true; };
  globalThis.fetch = (url, init) => {
    const signal = init ? init.signal : undefined;
    if (url !== '/link') {
      state.polls++;
      if (signal && signal.aborted) {
        return Promise.reject(abortError());
      }
      return Promise.resolve(respond(200, state.done ? '{"done":true,"level":"XAdES_BASELINE_LT"}' : '{"done":false}'));
    }
    state.links++;
    state.signals.push(signal);
    if (signal && signal.aborted) {
      return Promise.reject(abortError());
    }
    state.inFlight++;
    state.maxInFlight = Math.max(state.maxInFlight, state.inFlight);
    return new Promise((resolve, reject) => {
      let over = false;
      const end = () => {
        over = true;
        state.inFlight--;
      };
      const timer = setTimeout(() => {
        if (!over) {
          end();
          resolve(respond(200, JSON.stringify({ link: 'https://smart-id.com/dynamic-link/?n=' + state.links })));
        }
      }, linkDelay);
      if (signal) {
        signal.addEventListener('abort', () => {
          if (!over) {
            clearTimeout(timer);
            end();
            reject(abortError());
          }
        }, { once: true });
      }
    });
  };
  return state;
}

async function main() {
  // A server slower than the refresh: one request at a time, and a QR anyway.
  {
    const slow = server(45);
    const element = { innerHTML: '' };
    const running = allkiri.deviceLinkQr({ linkUrl: '/link', pollUrl: '/poll', element, interval: 20, pollInterval: 20, timeout: 3000 });
    await sleep(300);
    running.stop();
    await settleWithin(running.promise, 500);
    check('a slow link endpoint never has two requests at once', slow.maxInFlight === 1, slow.maxInFlight + ' at once');
    check('the loop still asks again once each answer is in', slow.links >= 3, slow.links + ' link requests');
    check('and the QR is drawn', element.innerHTML.indexOf('<svg') !== -1);
  }

  // A request that never answers is given up on and replaced.
  {
    const hung = server(60000);
    const running = allkiri.deviceLinkQr({ linkUrl: '/link', pollUrl: '/poll', element: { innerHTML: '' }, interval: 20, pollInterval: 20, timeout: 3000 });
    await sleep(150);
    check('a link request unanswered for three rounds is cancelled', hung.signals[0] !== undefined && hung.signals[0].aborted === true);
    check('and replaced by one request, not a pile of them', hung.links >= 2 && hung.maxInFlight === 1, hung.links + ' requests, ' + hung.maxInFlight + ' at once');
    running.stop();
    await settleWithin(running.promise, 500);
  }

  // stop() cancels the request it started.
  {
    const hung = server(60000);
    const running = allkiri.deviceLinkQr({ linkUrl: '/link', pollUrl: '/poll', element: { innerHTML: '' }, interval: 1000, pollInterval: 1000, timeout: 3000 });
    await sleep(30);
    running.stop();
    const asked = hung.links;
    check('stop() cancels the link request in flight', hung.signals[0] !== undefined && hung.signals[0].aborted === true);
    await sleep(50);
    check('and nothing is asked afterwards', hung.links === asked, asked + ' then ' + hung.links);
    const stopped = await settleWithin(running.promise, 500);
    check('the promise settles as cancelled', !stopped.late && stopped.error !== null && stopped.error.name === 'AbortError');
  }

  // A signal the page passed in stops everything, quietly.
  {
    const quick = server(5);
    const controller = new AbortController();
    let errors = 0;
    const running = allkiri.deviceLinkQr({
      linkUrl: '/link',
      pollUrl: '/poll',
      element: { innerHTML: '' },
      interval: 20,
      pollInterval: 20,
      timeout: 1000,
      signal: controller.signal,
      onError: () => { errors++; },
    });
    await sleep(60);
    controller.abort();
    const aborted = await settleWithin(running.promise, 300);
    check('the caller\'s abort rejects the promise at once', !aborted.late && aborted.error !== null && aborted.error.name === 'AbortError', aborted.late ? 'still waiting' : String(aborted.error));
    const links = quick.links;
    const polls = quick.polls;
    await sleep(100);
    check('and stops the redrawing and the polling', quick.links === links && quick.polls === polls, links + '/' + polls + ' then ' + quick.links + '/' + quick.polls);
    check('with no onError for requests it cancelled', errors === 0, errors + ' calls');
    running.stop();
  }

  // A finished session ends the redrawing too.
  {
    const finishing = server(5);
    const running = allkiri.deviceLinkQr({ linkUrl: '/link', pollUrl: '/poll', element: { innerHTML: '' }, interval: 20, pollInterval: 20, timeout: 3000 });
    await sleep(50);
    finishing.finish();
    const done = await settleWithin(running.promise, 500);
    check('the promise resolves with the finished answer', !done.late && done.value !== null && done.value.done === true);
    const links = finishing.links;
    await sleep(80);
    check('and no link is asked for afterwards', finishing.links === links, links + ' then ' + finishing.links);
  }

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
