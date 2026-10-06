package com.example.auth.exception;

import org.springframework.http.HttpStatus;

/** The request clashes with the current state of a resource. Maps to HTTP 409. */
public class ConflictException extends ApiException {

	private static final String CODE = "CONFLICT";

	public ConflictException(String message) {
		super(HttpStatus.CONFLICT, CODE, message);
	}

	public ConflictException(String code, String message) {
		super(HttpStatus.CONFLICT, code, message);
	}
}
