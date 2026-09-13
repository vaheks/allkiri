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
      });
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
      var timer = setTimeout(resolve, ms);
      if (signal) {
        signal.addEventListener('abort', function () {
          clearTimeout(timer);
          reject(abortError());
        }, { once: true });
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
   * @param {string} url
   * @param {{interval?: number, timeout?: number, signal?: AbortSignal, onTick?: Function}} [options]
   * @returns {Promise<object>}
   */
  function poll(url, options) {
    var settings = options || {};
    var interval = settings.interval || 1000;
    var deadline = Date.now() + (settings.timeout || 120000);

    function attempt() {
      if (settings.signal && settings.signal.aborted) {
        return Promise.reject(abortError());
      }
      if (Date.now() > deadline) {
        return Promise.reject(new Error('Gave up waiting'));
      }

      return post(url, undefined, settings).then(function (answer) {
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
      return library.authenticate({ challengeNonce: challenge.nonce }, options);
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
   * Returns a handle with `stop()`; the promise settles when the session does.
   *
   * @param {{linkUrl: string, pollUrl: string, element: Element, interval?: number, size?: number, level?: 'L'|'M', onError?: Function}} options
   * @returns {{promise: Promise<object>, stop: Function}}
   */
  function deviceLinkQr(options) {
    if (!qr) {
      throw new Error('allkiri-qr.js is not loaded; the QR flow needs it');
    }
    if (!options.element) {
      throw new Error('deviceLinkQr needs an element to draw into');
    }

    var controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var stopped = false;
    var timer = null;

    function draw() {
      if (stopped) {
        return;
      }
      post(options.linkUrl, undefined, options).then(function (answer) {
        if (stopped || !answer || !answer.link) {
          return;
        }
        options.element.innerHTML = qr.svg(answer.link, {
          size: options.size || 256,
          level: options.level || 'M',
          title: 'Smart-ID'
        });
      }).catch(function (error) {
        if (!stopped && options.onError) {
          options.onError(error);
        }
      });
    }

    draw();
    timer = setInterval(draw, options.interval || 1000);

    function stop() {
      stopped = true;
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
      if (controller) {
        controller.abort();
      }
    }

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

  return {
    configure: configure,
    post: post,
    poll: poll,
    cardLogin: cardLogin,
    cardSign: cardSign,
    notificationFlow: notificationFlow,
    deviceLinkQr: deviceLinkQr,
    showVerificationCode: showVerificationCode,
    qr: qr
  };
}));
