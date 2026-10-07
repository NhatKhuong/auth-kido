package com.example.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * {@code POST /api/auth/refresh} was rejected (architecture 01-overview.md sections 3 and 7).
 *
 * <p>One exception, one code and one message for every reason a refresh can fail — the token is
 * unknown, it expired, or it was already rotated away. Telling them apart would let an attacker
 * learn which of their guesses was closer, the same reasoning as
 * {@link InvalidCredentialsException}. For the same reason it is a 401 and never a 404: an unknown
 * token must not be reported as a missing resource.
 *
 * <p>The code differs from {@code INVALID_CREDENTIALS} because the client has to act differently:
 * a dead refresh token means "send the user back to login", not "the password was wrong". That
 * distinction is about which request failed, not about why it failed, so it leaks nothing.
 */
public class InvalidRefreshTokenException extends ApiException {

	public static final String CODE = "INVALID_REFRESH_TOKEN";

	public InvalidRefreshTokenException() {
		super(HttpStatus.UNAUTHORIZED, CODE, "Refresh token is invalid or expired");
	}
}
