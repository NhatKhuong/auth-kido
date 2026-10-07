package com.example.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Login was rejected (architecture 01-overview.md section 7).
 *
 * <p>Deliberately one exception for "no such user" and "wrong password", with one message: telling
 * them apart would let anyone enumerate which usernames exist. For the same reason this is a 401,
 * not a 404 — a missing account must not be reported as a missing resource.
 *
 * <p>It is an {@link ApiException} rather than a Spring Security {@code AuthenticationException}
 * because login is a business operation of the service layer here, not a filter-chain outcome:
 * that keeps it rendered by {@code GlobalExceptionHandler} with the project's error body.
 */
public class InvalidCredentialsException extends ApiException {

	public static final String CODE = "INVALID_CREDENTIALS";

	public InvalidCredentialsException() {
		super(HttpStatus.UNAUTHORIZED, CODE, "Username or password is incorrect");
	}
}
