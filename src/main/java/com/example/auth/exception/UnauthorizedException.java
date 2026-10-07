package com.example.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * The request carried a verifiable access token, but the account it names no longer exists.
 *
 * <p>Reuses the {@code UNAUTHORIZED} code of the authentication entry point on purpose: from a
 * client's point of view the outcome is identical — the credential it presented is no longer
 * usable — and the architecture keeps one code per status (section 7). No new error code is
 * introduced by backlog 0006 for this branch.
 *
 * <p>Not a 404: the account is not a resource the caller asked for, it is who the caller claims to
 * be, and answering 404 would make a stale token look like a missing endpoint.
 */
public class UnauthorizedException extends ApiException {

	/** The literal rendered by {@code security/JsonAuthenticationEntryPoint} as well. */
	public static final String CODE = "UNAUTHORIZED";

	public UnauthorizedException(String message) {
		super(HttpStatus.UNAUTHORIZED, CODE, message);
	}
}
