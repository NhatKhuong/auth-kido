package com.example.auth.dto.response;

import java.time.Duration;

/**
 * Successful authentication response. Field names and the {@code "Bearer"} token type are a system
 * contract (architecture 01-overview.md section 7) and must not change without a PM decision.
 *
 * @param accessToken  short-lived JWT, sent as {@code Authorization: Bearer <accessToken>}
 * @param refreshToken long-lived opaque token, only usable against {@code /api/auth/refresh}
 * @param tokenType    always {@value #TOKEN_TYPE_BEARER}
 * @param expiresIn    lifetime of {@code accessToken} in seconds
 */
public record LoginResponse(
		String accessToken,
		String refreshToken,
		String tokenType,
		long expiresIn) {

	public static final String TOKEN_TYPE_BEARER = "Bearer";

	/**
	 * Derives {@code expiresIn} from the configured access token lifetime, so the number a client
	 * schedules its refresh by can never disagree with the token's own {@code exp}.
	 */
	public static LoginResponse bearer(String accessToken, String refreshToken, Duration accessTokenExpiration) {
		return new LoginResponse(accessToken, refreshToken, TOKEN_TYPE_BEARER, accessTokenExpiration.toSeconds());
	}
}
