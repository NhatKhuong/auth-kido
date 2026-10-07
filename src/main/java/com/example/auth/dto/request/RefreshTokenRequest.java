package com.example.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

/**
 * Body of {@code POST /api/auth/refresh} (architecture 01-overview.md section 7).
 *
 * <p>A missing or blank field is a 400, not a 401: as with login, the request never reached the
 * point where a token could be judged.
 *
 * @param refreshToken the opaque token previously handed to the client
 */
public record RefreshTokenRequest(
		@NotBlank(message = "refreshToken is required") String refreshToken) {

	/** Omits the token: it is a credential-equivalent value and must not reach a log line. */
	@Override
	public String toString() {
		return "RefreshTokenRequest{}";
	}
}
