package com.example.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * A requested resource does not exist. Maps to HTTP 404.
 *
 * <p>Deliberately shares the {@code NOT_FOUND} code with an unmatched route: a client cannot
 * usefully act differently on "no such route" than on "no such record", so one code per status
 * keeps the contract smaller. Use the two-argument constructor only when a 404 genuinely needs
 * to be told apart by a client.
 */
public class ResourceNotFoundException extends ApiException {

	static final String CODE = "NOT_FOUND";

	public ResourceNotFoundException(String message) {
		super(HttpStatus.NOT_FOUND, CODE, message);
	}

	public ResourceNotFoundException(String code, String message) {
		super(HttpStatus.NOT_FOUND, code, message);
	}
}
