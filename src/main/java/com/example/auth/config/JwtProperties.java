package com.example.auth.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Token configuration, bound from the {@code jwt.*} keys in application.yml (which in turn read
 * the {@code JWT_*} environment variables described in {@code .env.example}).
 *
 * <p>The expirations are {@link Duration} rather than numbers so the unit lives in the
 * configuration value ({@code 15m}, {@code 7d}) instead of being an implicit convention, and so
 * the {@code expiresIn} field of the login response is derived from configuration rather than
 * duplicated as a literal.
 *
 * <p>No default is declared for {@code secret}: a signing key must never be committed. It is
 * validated — and startup fails — in {@code security/JwtService}.
 *
 * @param secret                 HMAC signing key for access tokens
 * @param accessTokenExpiration  how long an issued access token stays valid
 * @param refreshTokenExpiration how long a stored refresh token stays valid
 */
@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(
		String secret,
		Duration accessTokenExpiration,
		Duration refreshTokenExpiration) {
}
