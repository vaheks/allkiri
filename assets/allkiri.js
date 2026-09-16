/**
 * The browser half of allkiri.
 *
 * Every Estonian eID means needs something from the page: the ID card needs the
 * Web eID extension driven, Mobile-ID and Smart-ID need a verification code
 * shown and the server polled, and Smart-ID's QR flow needs a new code drawn
 * about once a second. None of that is hard, and all of it is easy to get
 * subtly wrong, so it is here rather than in every application's own script.
 *
 * What this does not do is decide anything. Every answer goes to your server,
 * which is where the signature is checked; a page cannot validate a signature
 * and must not pretend to. These helpers move bytes and draw things.
 *
 * No dependencies, no build step. For the ID card, load web-eid.js alongside
 * it: https://github.com/web-eid/web-eid.js
 *
 * MIT, like the rest of allkiri.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./allkiri-qr.js'));
  } else {
    root.allkiri = factory(root.allkiriQr);
  }
}(typeof self !== 'undefined' ? self : this, function (qr) {
  'use strict';

  // --- talking to your server ---------------------------------------------

  /**
   * Everything here posts JSON to your own endpoints and expects JSON back.
   * Override any of it if your application speaks differently.
   */
  var defaults = {
    headers: {},
    credentials: 'same-origin',
    csrfToken: null,
    csrfHeader: 'X-CSRF-Token'
  };

  function configure(options) {
    Object.keys(options || {}).forEach(function (key) {
      defaults[key] = options[key];
    });
  }

  /**
   * What a gateway in front of your server answers when it gave up on it or
   * could not reach it. The request may never have arrived.
   */
  var GATEWAY_STATUSES = [502, 503, 504];

  /**
   * A failure in which no answer from your server arrived: the network, or a
   * connection dropped while the answer was on its way. Marked, so that poll()
   * can tell it from anything your server actually said.
   */
  function noAnswer(failure) {
    if (failure && failure.name === 'AbortError') {
      return failure;
    }
    var error = failure instanceof Error ? failure : new Error(String(failure));
    error.transient = true;
    return error;
  }

  function post(url, body, options) {
    if (typeof url !== 'string' || url === '') {
      return Promise.reject(new Error('allkiri: no URL was given for this step'));
    }
    var settings = options || {};
    var headers = { 'Content-Type': 'application/json', Accept: 'application/json' };

    Object.keys(defaults.headers).forEach(function (k) { headers[k] = defaults.headers[k]; });
    Object.keys(settings.headers || {}).forEach(function (k) { headers[k] = settings.headers[k]; });
    if (defaults.csrfToken) {
      headers[defaults.csrfHeader] = defaults.csrfToken;
    }

    return fetch(url, {
      method: 'POST',
      headers: headers,
      credentials: settings.credentials || defaults.credentials,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: settings.signal
    }).then(function (response) {
      return response.text().then(function (text) {
        var payload = null;
        var parsed = false;
        try {
          payload = text === '' ? null : JSON.parse(text);
          parsed = true;
        } catch (e) {
          payload = null;
        }
        if (!response.ok) {
          var message = (payload && (payload.message || payload.error))
            || ('The server answered ' + response.status);
          var error = new Error(message);
          error.status = response.status;
          error.payload = payload;
          error.transient = GATEWAY_STATUSES.indexOf(response.status) !== -1;
          throw error;
        }
        // An answer that cannot be read is an error, not an empty answer.
        // Returning null here would let a polling loop read "I could not
        // understand the server" as "not finished yet", and carry on asking
        // until it gives up — long after the session it was waiting for was
        // finished and consumed. A PHP notice, a proxy's error page or an
        // HTML login redirect in front of your endpoints all land here.
        if (!parsed) {
          var unreadable = new Error(
            'The server answered ' + response.status + ' but not with JSON: ' + excerpt(text)
          );
          unreadable.status = response.status;
          unreadable.body = text;
          throw unreadable;
        }
        return payload;
      }, function (failure) {
        throw noAnswer(failure);
      });
    }, function (failure) {
      throw noAnswer(failure);
    });
  }

  /**
   * Enough of an unreadable body to recognise it, on one line.
   */
  function excerpt(text) {
    var flat = String(text).replace(/\s+/g, ' ').trim();
    return flat.length > 120 ? flat.slice(0, 120) + '…' : flat;
  }

  // --- waiting for a person ------------------------------------------------

  function delay(ms, signal) {
    return new Promise(function (resolve, reject) {
      if (signal && signal.aborted) {
        reject(abortError());
        return;
      }
      function onAbort() {
        clearTimeout(timer);
        reject(abortError());
      }
      // Removed when the wait ends, or a long poll leaves one listener per
      // round on the caller's signal.
      var timer = setTimeout(function () {
        if (signal) {
          signal.removeEventListener('abort', onAbort);
        }
        resolve();
      }, ms);
      if (signal) {
        signal.addEventListener('abort', onAbort, { once: true });
      }
    });
  }

  function abortError() {
    var error = new Error('Cancelled');
    error.name = 'AbortError';
    return error;
  }

  /**
   * Ask the server until it says the person is done.
   *
   * The server answers `{done: false}` while waiting and `{done: true, ...}`
   * when finished. It is the server that talks to SK and decides; this only
   * asks again.
   *
   * When no answer from the server arrives, or a gateway answers 502, 503 or
   * 504, it asks again after the interval, then after twice, four and eight
   * times it, never past the timeout. Anything the server did say ends the
   * wait at once. So an endpoint may be asked again about a session it already
   * finished, and should give the finished answer again for a little while.
   *
   * @param {string} url
   * @param {{interval?: number, timeout?: number, signal?: AbortSignal, onTick?: Function}} [options]
   * @returns {Promise<object>}
   */
  function poll(url, options) {
    var settings = options || {};
    var interval = settings.interval || 1000;
    var deadline = Date.now() + (settings.timeout || 120000);
    var failures = 0;
    var lastFailure = null;

    function attempt() {
      if (settings.signal && settings.signal.aborted) {
        return Promise.reject(abortError());
      }
      if (Date.now() > deadline) {
        return Promise.reject(lastFailure || new Error('Gave up waiting'));
      }

      return post(url, undefined, settings).then(function (answer) {
        failures = 0;
        lastFailure = null;
        // Same reasoning as the parse check in post(): only a real answer may
        // be read as "not finished yet".
        if (answer === null || typeof answer !== 'object') {
          throw new Error('The server did not answer this poll with an object');
        }
        if (answer.done) {
          return answer;
        }
        if (settings.onTick) {
          settings.onTick(answer);
        }
        return delay(interval, settings.signal).then(attempt);
      }, function (error) {
        // Only post()'s own failure is looked at here, so an error thrown by
        // onTick above is never mistaken for the network.
        if (!error || !error.transient) {
          throw error;
        }
        // Set before the deadline is looked at, so a failure that arrives after
        // it still says how many times the poll had already asked again.
        error.retries = failures;
        failures++;
        lastFailure = error;
        var left = deadline - Date.now();
        if (left <= 0) {
          throw error;
        }
        var wait = Math.min(interval * Math.pow(2, Math.min(failures - 1, 3)), left);
        return delay(wait, settings.signal).then(attempt);
      });
    }

    return attempt();
  }

  // --- the ID card, through Web eID ---------------------------------------

  function webeid() {
    var library = typeof window !== 'undefined' && window.webeid;
    if (!library) {
      throw new Error('web-eid.js is not loaded; the ID card needs it. See https://github.com/web-eid/web-eid.js');
    }
    return library;
  }

  /**
   * Sign in with an ID card.
   *
   * Asks your server for a challenge, has the card sign it, and posts the token
   * back. Nothing is decided here: your server checks the token.
   *
   * @param {{challengeUrl: string, loginUrl: string, lang?: string}} urls
   * @returns {Promise<object>} whatever your login endpoint returns
   */
  function cardLogin(urls) {
    var options = urls.lang ? { lang: urls.lang } : undefined;
    // Check the browser can do this before asking the server for a challenge.
    // Otherwise a page without the extension leaves a session open on the
    // server that nothing will ever answer.
    var library;
    try {
      library = webeid();
    } catch (error) {
      return Promise.reject(error);
    }

    return post(urls.challengeUrl, undefined, urls).then(function (challenge) {
      if (!challenge || !challenge.nonce) {
        throw new Error('The server did not return a challenge');
      }
      // The nonce itself, not an object holding it: web-eid.js passes this on
      // unchanged, and the native application reads anything but a string as
      // an empty nonce and fails before it touches the card.
      return library.authenticate(challenge.nonce, options);
    }).then(function (token) {
      return post(urls.loginUrl, { token: JSON.stringify(token) }, urls);
    });
  }

  /**
   * Sign a document with an ID card.
   *
   * Four steps, two of them on your server: fetch the certificate, have the
   * server prepare, sign the digest with PIN 2, have the server finish.
   *
   * @param {{prepareUrl: string, completeUrl: string, lang?: string}} urls
   * @returns {Promise<object>} whatever your completion endpoint returns
   */
  function cardSign(urls) {
    var options = urls.lang ? { lang: urls.lang } : undefined;
    var library;
    try {
      library = webeid();
    } catch (error) {
      return Promise.reject(error);
    }
    var certificate;

    return library.getSigningCertificate(options).then(function (result) {
      certificate = result.certificate;
      return post(urls.prepareUrl, {
        certificate: result.certificate,
        supportedSignatureAlgorithms: result.supportedSignatureAlgorithms
      }, urls);
    }).then(function (prepared) {
      if (!prepared || !prepared.hash || !prepared.hashFunction) {
        throw new Error('The server did not return anything to sign');
      }
      return library.sign(certificate, prepared.hash, prepared.hashFunction, options);
    }).then(function (signed) {
      return post(urls.completeUrl, {
        signature: signed.signature,
        signatureAlgorithm: signed.signatureAlgorithm
      }, urls);
    });
  }

  // --- Mobile-ID and Smart-ID, by notification -----------------------------

  /**
   * Start something the person confirms on their phone, then wait for it.
   *
   * Your start endpoint returns `{verificationCode: "1234"}`; this shows it and
   * polls until the server says the session finished.
   *
   * @param {{startUrl: string, pollUrl: string, body?: object, onCode?: Function, interval?: number, timeout?: number, signal?: AbortSignal}} options
   * @returns {Promise<object>}
   */
  function notificationFlow(options) {
    return post(options.startUrl, options.body || {}, options).then(function (started) {
      if (started && started.verificationCode && options.onCode) {
        options.onCode(started.verificationCode, started);
      }
      return poll(options.pollUrl, options);
    });
  }

  // --- Smart-ID device links ----------------------------------------------

  /**
   * Show a Smart-ID QR code, refreshing it as the protocol requires.
   *
   * A device-link QR carries how many seconds have passed since the session
   * started, and the app refuses a stale one, so a new link — with a new
   * authentication code — is needed about once a second. Only your server can
   * mint those: the session secret that signs them must never reach a browser.
   * So this asks the server for each new link rather than building any itself.
   *
   * Returns a handle with `stop()`. The promise settles when the session does,
   * and rejects as cancelled once `stop()` is called or `signal` aborts.
   *
   * One link request is in flight at a time, so a slow server is not asked
   * again before it has answered. A request still unanswered after three
   * intervals is cancelled and replaced, since the link it would bring back is
   * stale. `stop()` cancels the request in flight.
   *
   * @param {{linkUrl: string, pollUrl: string, element: Element, interval?: number, pollInterval?: number, timeout?: number, size?: number, level?: 'L'|'M', signal?: AbortSignal, headers?: object, credentials?: string, onError?: Function}} options
   * @returns {{promise: Promise<object>, stop: Function}}
   */
  function deviceLinkQr(options) {
    if (!qr) {
      throw new Error('allkiri-qr.js is not loaded; the QR flow needs it');
    }
    if (!options.element) {
      throw new Error('deviceLinkQr needs an element to draw into');
    }

    var interval = options.interval || 1000;
    var controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var stopped = false;
    var timer = null;
    var inFlight = null;

    function draw() {
      timer = null;
      if (stopped) {
        return;
      }
      if (inFlight !== null) {
        if (Date.now() - inFlight.startedAt < interval * 3) {
          schedule();
          return;
        }
        // Unanswered for three rounds: whatever it brings back is stale.
        if (inFlight.controller) {
          inFlight.controller.abort();
        }
        inFlight = null;
      }

      var request = {
        controller: typeof AbortController !== 'undefined' ? new AbortController() : null,
        startedAt: Date.now()
      };
      inFlight = request;
      post(options.linkUrl, undefined, {
        headers: options.headers,
        credentials: options.credentials,
        signal: request.controller ? request.controller.signal : undefined
      }).then(function (answer) {
        if (inFlight === request) {
          inFlight = null;
        }
        if (stopped || !answer || !answer.link) {
          return;
        }
        options.element.innerHTML = qr.svg(answer.link, {
          size: options.size || 256,
          level: options.level || 'M',
          title: 'Smart-ID'
        });
      }, function (error) {
        if (inFlight === request) {
          inFlight = null;
        }
        // A request this loop cancelled itself is not worth reporting.
        if (!stopped && options.onError && !(error && error.name === 'AbortError')) {
          options.onError(error);
        }
      });
      schedule();
    }

    function schedule() {
      if (!stopped && timer === null) {
        timer = setTimeout(draw, interval);
      }
    }

    function stop() {
      if (stopped) {
        return;
      }
      stopped = true;
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
      if (inFlight !== null && inFlight.controller) {
        inFlight.controller.abort();
      }
      inFlight = null;
      if (controller) {
        controller.abort();
      }
      if (options.signal) {
        options.signal.removeEventListener('abort', stop);
      }
    }

    // The page's own signal stops everything, as stop() does.
    if (options.signal) {
      if (options.signal.aborted) {
        stop();
      } else {
        options.signal.addEventListener('abort', stop, { once: true });
      }
    }

    draw();

    var promise = poll(options.pollUrl, {
      interval: options.pollInterval || 1500,
      timeout: options.timeout,
      signal: controller ? controller.signal : options.signal,
      headers: options.headers,
      credentials: options.credentials
    });

    // Stop redrawing as soon as there is an answer, either way.
    promise.then(stop, function () { stop(); });

    return { promise: promise, stop: stop };
  }

  // --- small conveniences --------------------------------------------------

  /**
   * Put a verification code on the page, in a shape people can read at a
   * glance. Four digits, spaced.
   */
  function showVerificationCode(element, code) {
    if (!element) {
      return;
    }
    element.textContent = String(code).split('').join(' ');
    element.setAttribute('aria-label', 'Verification code ' + String(code).split('').join(' '));
  }

  // --- when the ID card fails ------------------------------------------------

  var PROBLEM_ON_THIS_SITE = 'The ID card could not be used because of a problem on this site. Try again later.';

  /**
   * Who can act on each error code of web-eid.js 2.x, and what to tell them.
   */
  var WEB_EID_PROBLEMS = {
    ERR_WEBEID_EXTENSION_UNAVAILABLE: {
      who: 'person',
      text: 'The Web eID browser extension is not installed or not turned on. Install or enable it, then try again.'
    },
    ERR_WEBEID_NATIVE_UNAVAILABLE: {
      who: 'person',
      text: 'The Web eID application is not installed. Install the ID card software, which includes it, then try again.'
    },
    ERR_WEBEID_VERSION_MISMATCH: { who: 'person', text: '' },
    ERR_WEBEID_USER_CANCELLED: {
      who: 'person',
      text: 'The ID card request was cancelled. Start again when you are ready.'
    },
    ERR_WEBEID_USER_TIMEOUT: {
      who: 'person',
      text: 'Nothing was entered in time. Try again.'
    },
    ERR_WEBEID_NATIVE_FATAL: {
      who: 'person',
      text: 'The ID card could not be used. Check that it is in the reader and try again; if it keeps happening, the reader or the card may be at fault.'
    },
    ERR_WEBEID_CONTEXT_INSECURE: {
      who: 'operator',
      text: 'This page is not served over HTTPS, and the ID card only works on a secure page.'
    },
    ERR_WEBEID_NATIVE_INVALID_ARGUMENT: { who: 'developer', text: PROBLEM_ON_THIS_SITE },
    ERR_WEBEID_ACTION_PENDING: { who: 'developer', text: PROBLEM_ON_THIS_SITE },
    ERR_WEBEID_MISSING_PARAMETER: { who: 'developer', text: PROBLEM_ON_THIS_SITE },
    ERR_WEBEID_ACTION_TIMEOUT: { who: 'developer', text: PROBLEM_ON_THIS_SITE },
    ERR_WEBEID_VERSION_INVALID: { who: 'developer', text: PROBLEM_ON_THIS_SITE },
    ERR_WEBEID_UNKNOWN_ERROR: { who: 'developer', text: PROBLEM_ON_THIS_SITE }
  };

  /**
   * What to tell someone whose ID card failed.
   *
   * cardLogin() and cardSign() reject with web-eid.js's own error, whose
   * message is written for developers and belongs in your logs. Given that
   * error, this says who can act on it (the person at the card, the site's
   * operator, or its developers) and gives a sentence in English for them.
   * Anything that is not a known web-eid.js 2.x error gives null, so your own
   * handling applies.
   *
   * @param {*} error
   * @returns {{code: string, who: string, text: string}|null}
   */
  function describeWebEidError(error) {
    var code = error && typeof error.code === 'string' ? error.code : null;
    if (code === null || !Object.prototype.hasOwnProperty.call(WEB_EID_PROBLEMS, code)) {
      return null;
    }
    var problem = WEB_EID_PROBLEMS[code];
    return {
      code: code,
      who: problem.who,
      text: code === 'ERR_WEBEID_VERSION_MISMATCH' ? outOfDate(error.requiresUpdate) : problem.text
    };
  }

  /**
   * web-eid.js says which of its parts is out of date in requiresUpdate.
   */
  function outOfDate(requiresUpdate) {
    var extension = !!(requiresUpdate && requiresUpdate.extension);
    var application = !!(requiresUpdate && requiresUpdate.nativeApp);
    if (extension && application) {
      return 'The Web eID browser extension and application are out of date. Update both, then try again.';
    }
    if (extension) {
      return 'The Web eID browser extension is out of date. Update it, then try again.';
    }
    if (application) {
      return 'The Web eID application is out of date. Update the ID card software, then try again.';
    }
    return 'Web eID is out of date. Update the browser extension and the ID card software, then try again.';
  }

  return {
    configure: configure,
    post: post,
    poll: poll,
    cardLogin: cardLogin,
    cardSign: cardSign,
    describeWebEidError: describeWebEidError,
    notificationFlow: notificationFlow,
    deviceLinkQr: deviceLinkQr,
    showVerificationCode: showVerificationCode,
    qr: qr
  };
}));
