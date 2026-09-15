/**
 * MIT License
 *
 * Copyright (c) 2020-2025 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

var webeid = (function (exports) {
    'use strict';

    var Action;
    (function (Action) {
        Action["WARNING"] = "web-eid:warning";
        Action["STATUS"] = "web-eid:status";
        Action["STATUS_ACK"] = "web-eid:status-ack";
        Action["STATUS_SUCCESS"] = "web-eid:status-success";
        Action["STATUS_FAILURE"] = "web-eid:status-failure";
        Action["AUTHENTICATE"] = "web-eid:authenticate";
        Action["AUTHENTICATE_ACK"] = "web-eid:authenticate-ack";
        Action["AUTHENTICATE_SUCCESS"] = "web-eid:authenticate-success";
        Action["AUTHENTICATE_FAILURE"] = "web-eid:authenticate-failure";
        Action["GET_SIGNING_CERTIFICATE"] = "web-eid:get-signing-certificate";
        Action["GET_SIGNING_CERTIFICATE_ACK"] = "web-eid:get-signing-certificate-ack";
        Action["GET_SIGNING_CERTIFICATE_SUCCESS"] = "web-eid:get-signing-certificate-success";
        Action["GET_SIGNING_CERTIFICATE_FAILURE"] = "web-eid:get-signing-certificate-failure";
        Action["SIGN"] = "web-eid:sign";
        Action["SIGN_ACK"] = "web-eid:sign-ack";
        Action["SIGN_SUCCESS"] = "web-eid:sign-success";
        Action["SIGN_FAILURE"] = "web-eid:sign-failure";
    })(Action || (Action = {}));
    var Action$1 = Action;

    var ErrorCode;
    (function (ErrorCode) {
        ErrorCode["ERR_WEBEID_ACTION_TIMEOUT"] = "ERR_WEBEID_ACTION_TIMEOUT";
        ErrorCode["ERR_WEBEID_USER_TIMEOUT"] = "ERR_WEBEID_USER_TIMEOUT";
        ErrorCode["ERR_WEBEID_VERSION_MISMATCH"] = "ERR_WEBEID_VERSION_MISMATCH";
        ErrorCode["ERR_WEBEID_VERSION_INVALID"] = "ERR_WEBEID_VERSION_INVALID";
        ErrorCode["ERR_WEBEID_EXTENSION_UNAVAILABLE"] = "ERR_WEBEID_EXTENSION_UNAVAILABLE";
        ErrorCode["ERR_WEBEID_NATIVE_UNAVAILABLE"] = "ERR_WEBEID_NATIVE_UNAVAILABLE";
        ErrorCode["ERR_WEBEID_UNKNOWN_ERROR"] = "ERR_WEBEID_UNKNOWN_ERROR";
        ErrorCode["ERR_WEBEID_CONTEXT_INSECURE"] = "ERR_WEBEID_CONTEXT_INSECURE";
        ErrorCode["ERR_WEBEID_USER_CANCELLED"] = "ERR_WEBEID_USER_CANCELLED";
        ErrorCode["ERR_WEBEID_NATIVE_INVALID_ARGUMENT"] = "ERR_WEBEID_NATIVE_INVALID_ARGUMENT";
        ErrorCode["ERR_WEBEID_NATIVE_FATAL"] = "ERR_WEBEID_NATIVE_FATAL";
        ErrorCode["ERR_WEBEID_ACTION_PENDING"] = "ERR_WEBEID_ACTION_PENDING";
        ErrorCode["ERR_WEBEID_MISSING_PARAMETER"] = "ERR_WEBEID_MISSING_PARAMETER";
    })(ErrorCode || (ErrorCode = {}));
    var ErrorCode$1 = ErrorCode;

    class DeveloperError extends Error {
        constructor(message) {
            super(message);
        }
    }

    class MissingParameterError extends DeveloperError {
        constructor(message) {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_MISSING_PARAMETER;
        }
    }

    class ActionTimeoutError extends Error {
        constructor(message = "extension message timeout") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_ACTION_TIMEOUT;
        }
    }

    const SECURE_CONTEXTS_INFO_URL = "https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts";
    class ContextInsecureError extends Error {
        constructor(message = "Secure context required, see " + SECURE_CONTEXTS_INFO_URL) {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_CONTEXT_INSECURE;
        }
    }

    class ExtensionUnavailableError extends Error {
        constructor(message = "Web-eID extension is not available") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_EXTENSION_UNAVAILABLE;
        }
    }

    class NativeFatalError extends Error {
        constructor(message = "native application terminated with a fatal error") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_NATIVE_FATAL;
        }
    }

    class NativeUnavailableError extends Error {
        constructor(message = "Web-eID native application is not available") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_NATIVE_UNAVAILABLE;
        }
    }

    class UnknownError extends Error {
        constructor(message = "an unknown error occurred") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_UNKNOWN_ERROR;
        }
    }

    class UserCancelledError extends Error {
        constructor(message = "request was cancelled by the user") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_USER_CANCELLED;
        }
    }

    class UserTimeoutError extends Error {
        constructor(message = "user failed to respond in time") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_USER_TIMEOUT;
        }
    }

    class VersionInvalidError extends Error {
        constructor(message = "invalid version string") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_VERSION_INVALID;
        }
    }

    function tmpl(strings, requiresUpdate) {
        return `Update required for Web-eID ${requiresUpdate}`;
    }
    class VersionMismatchError extends Error {
        constructor(message, versions, requiresUpdate) {
            if (!message) {
                if (!requiresUpdate) {
                    message = "requiresUpdate not provided";
                }
                else if (requiresUpdate.extension && requiresUpdate.nativeApp) {
                    message = tmpl `${"extension and native app"}`;
                }
                else if (requiresUpdate.extension) {
                    message = tmpl `${"extension"}`;
                }
                else if (requiresUpdate.nativeApp) {
                    message = tmpl `${"native app"}`;
                }
            }
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_VERSION_MISMATCH;
            this.requiresUpdate = requiresUpdate ?? { nativeApp: false, extension: false };
            if (versions) {
                const { library, extension, nativeApp } = versions;
                Object.assign(this, { library, extension, nativeApp });
            }
        }
    }

    class ActionPendingError extends DeveloperError {
        constructor(message = "same action for Web-eID browser extension is already pending") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_ACTION_PENDING;
        }
    }

    var config = Object.freeze({
        VERSION: "2.1.0",
        EXTENSION_HANDSHAKE_TIMEOUT: 1000,
        NATIVE_APP_HANDSHAKE_TIMEOUT: 5 * 1000,
        DEFAULT_USER_INTERACTION_TIMEOUT: 2 * 60 * 1000,
        MAX_EXTENSION_LOAD_DELAY: 1000,
    });

    class NativeInvalidArgumentError extends DeveloperError {
        constructor(message = "native application received an invalid argument") {
            super(message);
            this.name = this.constructor.name;
            this.code = ErrorCode$1.ERR_WEBEID_NATIVE_INVALID_ARGUMENT;
        }
    }

    const errorCodeToErrorClass = {
        [ErrorCode$1.ERR_WEBEID_ACTION_PENDING]: ActionPendingError,
        [ErrorCode$1.ERR_WEBEID_ACTION_TIMEOUT]: ActionTimeoutError,
        [ErrorCode$1.ERR_WEBEID_CONTEXT_INSECURE]: ContextInsecureError,
        [ErrorCode$1.ERR_WEBEID_EXTENSION_UNAVAILABLE]: ExtensionUnavailableError,
        [ErrorCode$1.ERR_WEBEID_MISSING_PARAMETER]: MissingParameterError,
        [ErrorCode$1.ERR_WEBEID_NATIVE_INVALID_ARGUMENT]: NativeInvalidArgumentError,
        [ErrorCode$1.ERR_WEBEID_NATIVE_FATAL]: NativeFatalError,
        [ErrorCode$1.ERR_WEBEID_NATIVE_UNAVAILABLE]: NativeUnavailableError,
        [ErrorCode$1.ERR_WEBEID_USER_CANCELLED]: UserCancelledError,
        [ErrorCode$1.ERR_WEBEID_USER_TIMEOUT]: UserTimeoutError,
        [ErrorCode$1.ERR_WEBEID_VERSION_INVALID]: VersionInvalidError,
        [ErrorCode$1.ERR_WEBEID_VERSION_MISMATCH]: VersionMismatchError,
        [ErrorCode$1.ERR_WEBEID_UNKNOWN_ERROR]: UnknownError,
    };
    function isSerializedError(obj) {
        if (typeof obj !== "object" || obj === null) {
            return false;
        }
        const errorObject = obj;
        return (typeof errorObject.code === "string" &&
            typeof errorObject.message === "string" &&
            errorCodeToErrorClass[errorObject.code] != null);
    }
    function deserializeError(errorObject) {
        let error;
        if (isSerializedError(errorObject)) {
            const CustomError = errorCodeToErrorClass[errorObject.code];
            error = new CustomError();
            Object.entries(errorObject).forEach(([key, value]) => {
                Reflect.set(error, key, value);
            });
        }
        else {
            error = new UnknownError();
            const unknownObject = errorObject;
            if (unknownObject?.stack)
                error.stack = unknownObject.stack;
            if (unknownObject?.message)
                error.message = unknownObject.message;
        }
        return error;
    }

    class WebExtensionService {
        constructor() {
            this.loggedWarnings = [];
            this.queue = [];
            window.addEventListener("message", (event) => this.receive(event));
        }
        receive(event) {
            if (typeof event.data?.action !== "string")
                return;
            if (!event.data.action.startsWith("web-eid:"))
                return;
            const message = event.data;
            const suffix = ["success", "failure", "ack"].find((s) => message.action.endsWith(s));
            const initialAction = this.getInitialAction(message.action);
            const pending = this.getPendingMessage(initialAction);
            if (message.action === Action$1.WARNING) {
                message.warnings?.forEach((warning) => {
                    if (!this.loggedWarnings.includes(warning)) {
                        this.loggedWarnings.push(warning);
                        console.warn(warning.replace(/\n|\r/g, ""));
                    }
                });
            }
            else if (pending) {
                switch (suffix) {
                    case "ack": {
                        clearTimeout(pending.ackTimer);
                        break;
                    }
                    case "success": {
                        this.removeFromQueue(initialAction);
                        pending.resolve?.(message);
                        break;
                    }
                    case "failure": {
                        const failureMessage = message;
                        this.removeFromQueue(initialAction);
                        pending.reject?.(deserializeError(failureMessage.error));
                        break;
                    }
                }
            }
        }
        send(message, timeout) {
            if (this.getPendingMessage(message.action)) {
                return Promise.reject(new ActionPendingError());
            }
            else if (!window.isSecureContext) {
                return Promise.reject(new ContextInsecureError());
            }
            else {
                const pending = { message };
                this.queue.push(pending);
                pending.promise = new Promise((resolve, reject) => {
                    pending.resolve = resolve;
                    pending.reject = reject;
                });
                pending.ackTimer = window.setTimeout(() => this.onAckTimeout(pending), config.EXTENSION_HANDSHAKE_TIMEOUT);
                pending.replyTimer = window.setTimeout(() => this.onReplyTimeout(pending), timeout);
                window.postMessage(message, "*");
                return pending.promise;
            }
        }
        onReplyTimeout(pending) {
            this.removeFromQueue(pending.message.action);
            pending.reject?.(new ActionTimeoutError());
        }
        onAckTimeout(pending) {
            clearTimeout(pending.replyTimer);
            this.removeFromQueue(pending.message.action);
            pending.reject?.(new ExtensionUnavailableError());
        }
        getPendingMessage(action) {
            return this.queue.find((pm) => {
                return pm.message.action === action;
            });
        }
        getInitialAction(action) {
            return action.replace(/-success$|-failure$|-ack$/, "");
        }
        removeFromQueue(action) {
            const pending = this.getPendingMessage(action);
            clearTimeout(pending?.replyTimer);
            this.queue = this.queue.filter((pending) => (pending.message.action !== action));
        }
    }

    /**
     * Sleeps for a specified time before resolving the returned promise.
     *
     * @param milliseconds Time in milliseconds until the promise is resolved
     *
     * @returns Empty promise
     */
    function sleep(milliseconds) {
        return new Promise((resolve) => {
            setTimeout(() => resolve(), milliseconds);
        });
    }

    const webExtensionService = new WebExtensionService();
    const initializationTime = +new Date();
    async function extensionLoadDelay() {
        const now = +new Date();
        await sleep(initializationTime + config.MAX_EXTENSION_LOAD_DELAY - now);
    }
    async function status() {
        await extensionLoadDelay();
        const timeout = config.EXTENSION_HANDSHAKE_TIMEOUT + config.NATIVE_APP_HANDSHAKE_TIMEOUT;
        const message = {
            action: Action$1.STATUS,
            libraryVersion: config.VERSION,
        };
        try {
            const { library, extension, nativeApp, } = await webExtensionService.send(message, timeout);
            return {
                library,
                extension,
                nativeApp,
            };
        }
        catch (error) {
            if (error instanceof Error) {
                Reflect.set(error, "library", config.VERSION);
            }
            throw error;
        }
    }
    async function authenticate(challengeNonce, options) {
        await extensionLoadDelay();
        if (!challengeNonce) {
            throw new MissingParameterError("authenticate function requires a challengeNonce");
        }
        const timeout = (config.EXTENSION_HANDSHAKE_TIMEOUT +
            config.NATIVE_APP_HANDSHAKE_TIMEOUT +
            (options?.userInteractionTimeout ?? config.DEFAULT_USER_INTERACTION_TIMEOUT));
        const message = {
            action: Action$1.AUTHENTICATE,
            libraryVersion: config.VERSION,
            challengeNonce,
            options,
        };
        const { unverifiedCertificate, algorithm, signature, format, appVersion, } = await webExtensionService.send(message, timeout);
        return {
            unverifiedCertificate,
            algorithm,
            signature,
            format,
            appVersion,
        };
    }
    async function getSigningCertificate(options) {
        await extensionLoadDelay();
        const timeout = (config.EXTENSION_HANDSHAKE_TIMEOUT +
            config.NATIVE_APP_HANDSHAKE_TIMEOUT +
            (options?.userInteractionTimeout ?? config.DEFAULT_USER_INTERACTION_TIMEOUT) * 2);
        const message = {
            action: Action$1.GET_SIGNING_CERTIFICATE,
            libraryVersion: config.VERSION,
            options,
        };
        const { certificate, supportedSignatureAlgorithms, } = await webExtensionService.send(message, timeout);
        return {
            certificate,
            supportedSignatureAlgorithms,
        };
    }
    async function sign(certificate, hash, hashFunction, options) {
        await extensionLoadDelay();
        if (!certificate) {
            throw new MissingParameterError("sign function requires a certificate as parameter");
        }
        if (!hash) {
            throw new MissingParameterError("sign function requires a hash as parameter");
        }
        if (!hashFunction) {
            throw new MissingParameterError("sign function requires a hashFunction as parameter");
        }
        const timeout = (config.EXTENSION_HANDSHAKE_TIMEOUT +
            config.NATIVE_APP_HANDSHAKE_TIMEOUT +
            (options?.userInteractionTimeout ?? config.DEFAULT_USER_INTERACTION_TIMEOUT) * 2);
        const message = {
            action: Action$1.SIGN,
            libraryVersion: config.VERSION,
            certificate,
            hash,
            hashFunction,
            options,
        };
        const { signature, signatureAlgorithm, } = await webExtensionService.send(message, timeout);
        return {
            signature,
            signatureAlgorithm,
        };
    }

    exports.Action = Action$1;
    exports.ActionTimeoutError = ActionTimeoutError;
    exports.ContextInsecureError = ContextInsecureError;
    exports.DeveloperError = DeveloperError;
    exports.ErrorCode = ErrorCode$1;
    exports.ExtensionUnavailableError = ExtensionUnavailableError;
    exports.NativeFatalError = NativeFatalError;
    exports.NativeUnavailableError = NativeUnavailableError;
    exports.UnknownError = UnknownError;
    exports.UserCancelledError = UserCancelledError;
    exports.UserTimeoutError = UserTimeoutError;
    exports.VersionInvalidError = VersionInvalidError;
    exports.VersionMismatchError = VersionMismatchError;
    exports.authenticate = authenticate;
    exports.config = config;
    exports.getSigningCertificate = getSigningCertificate;
    exports.sign = sign;
    exports.status = status;

    return exports;

})({});
//# sourceMappingURL=web-eid.js.map
