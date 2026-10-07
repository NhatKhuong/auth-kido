'use strict';

/*
 * Shared browser-side helper for the static UI (backlog 0009, architecture 01-overview.md
 * section 11).
 *
 * Plain script, no module system and no dependencies: ADR 0001 decision 5 rules out npm and a
 * bundler, so every page loads this file with a <script> tag and uses the `Api` global.
 *
 * This file only consumes the API of backlog 0004-0007. It must never define a request shape of
 * its own: the endpoints, bodies and status codes are the system contract.
 */
const Api = (function () {

	/*
	 * sessionStorage, not localStorage: the access token lives 15 minutes and should not outlive
	 * the browser tab. Nothing here is a long-term credential store.
	 *
	 * The refresh token is deliberately not kept. This UI reacts to an expired access token by
	 * sending the user back to the login form (step 4 of the ticket); storing a 7-day credential
	 * the pages never use would only widen what an XSS could steal.
	 */
	const TOKEN_KEY = 'accessToken';
	const LOGIN_PAGE = 'login.html';

	/** Carries the server's `{code, message}` so a page can show the API's own wording. */
	class ApiError extends Error {
		constructor(status, code, message) {
			super(message);
			this.name = 'ApiError';
			this.status = status;
			this.code = code;
		}
	}

	function storeAccessToken(token) {
		sessionStorage.setItem(TOKEN_KEY, token);
	}

	function accessToken() {
		return sessionStorage.getItem(TOKEN_KEY);
	}

	function clearAccessToken() {
		sessionStorage.removeItem(TOKEN_KEY);
	}

	function goToLogin() {
		// replace() and not assign(): the page the user was thrown out of must not come back on
		// the browser's back button with a token that is already gone.
		window.location.replace(LOGIN_PAGE);
	}

	/** Sends a page straight to the login form when it is opened without a token at all. */
	function requireAccessToken() {
		const token = accessToken();
		if (!token) {
			goToLogin();
			return false;
		}
		return true;
	}

	async function toApiError(response) {
		let code = 'UNKNOWN_ERROR';
		let message = 'Request failed with status ' + response.status;
		try {
			const body = await response.json();
			// Every failing endpoint answers {code, message} (architecture section 7), but a
			// proxy or a non-API path can still answer something else.
			if (body && typeof body.code === 'string') {
				code = body.code;
			}
			if (body && typeof body.message === 'string' && body.message !== '') {
				message = body.message;
			}
		}
		catch (ignored) {
			// Body was absent or not JSON; the status-based fallback above stands.
		}
		return new ApiError(response.status, code, message);
	}

	/**
	 * One fetch wrapper for every call: attaches `Authorization: Bearer <accessToken>`, raises an
	 * ApiError carrying `{code, message}` on failure, and returns the parsed body (null for 204).
	 *
	 * A 401 means the token is missing, invalid or expired, so the token is dropped and the user
	 * is sent to the login form. The login call itself passes `redirectOnUnauthorized: false`:
	 * there a 401 is "wrong username or password" and has to be shown, not redirected away.
	 */
	async function request(path, options) {
		const settings = options || {};
		const headers = new Headers(settings.headers || {});
		const token = accessToken();
		if (token) {
			headers.set('Authorization', 'Bearer ' + token);
		}
		if (settings.body !== undefined) {
			headers.set('Content-Type', 'application/json');
		}
		headers.set('Accept', 'application/json');

		const response = await fetch(path, {
			method: settings.method || 'GET',
			headers: headers,
			body: settings.body
		});

		if (response.status === 401 && settings.redirectOnUnauthorized !== false) {
			clearAccessToken();
			goToLogin();
			throw await toApiError(response);
		}
		if (!response.ok) {
			throw await toApiError(response);
		}
		if (response.status === 204) {
			return null;
		}
		return response.json();
	}

	return {
		ApiError: ApiError,
		storeAccessToken: storeAccessToken,
		accessToken: accessToken,
		clearAccessToken: clearAccessToken,
		goToLogin: goToLogin,
		requireAccessToken: requireAccessToken,
		request: request
	};
})();
