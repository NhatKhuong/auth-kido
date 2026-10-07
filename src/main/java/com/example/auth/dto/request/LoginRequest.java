package com.example.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

/**
 * Body of {@code POST /api/auth/login} (architecture 01-overview.md section 7).
 *
 * <p>A missing or blank field is a 400, not a failed login: the request never reached the point
 * where credentials could be judged.
 *
 * @param username account to authenticate
 * @param password plaintext password, used once and never stored or logged
 */
public record LoginRequest(
		@NotBlank(message = "username is required") String username,
		@NotBlank(message = "password is required") String password) {

	/** Omits the password: request objects end up in debug logs and exception messages. */
	@Override
	public String toString() {
		return "LoginRequest{username='" + username + "'}";
	}
}
