package com.example.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Base class for failures that carry their own API contract: an error code and an HTTP status.
 *
 * <p>Carrying the status on the exception keeps the mapping next to the business rule that
 * raises it, so {@link GlobalExceptionHandler} needs one handler for all of them instead of
 * growing a branch per new failure.
 */
public abstract class ApiException extends RuntimeException {

	private final HttpStatus status;
	private final String code;

	protected ApiException(HttpStatus status, String code, String message) {
		super(message);
		this.status = status;
		this.code = code;
	}

	public HttpStatus getStatus() {
		return status;
	}

	public String getCode() {
		return code;
	}
}
