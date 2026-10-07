package com.example.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * The {@code currentPassword} supplied to {@code PUT /api/users/me/password} does not match the
 * stored hash (backlog 0006 contract).
 *
 * <p>400 rather than 401: the caller is authenticated and stays authenticated — their access token
 * is fine, one field of the body is not. Answering 401 would tell a client to throw away a working
 * token and refresh.
 *
 * <p>A distinct code from {@code VALIDATION_ERROR} because this is the one 400 the client can act
 * on differently: the field was well-formed, it was simply wrong.
 */
public class InvalidCurrentPasswordException extends ApiException {

	public static final String CODE = "INVALID_CURRENT_PASSWORD";

	public InvalidCurrentPasswordException() {
		super(HttpStatus.BAD_REQUEST, CODE, "Current password is incorrect");
	}
}
