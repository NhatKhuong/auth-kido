package com.example.auth.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.config.JwtProperties;
import com.example.auth.entity.Permission;
import com.example.auth.entity.Role;
import com.example.auth.entity.User;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Covers the access token requirements of architecture 01-overview.md section 9: the token is
 * created correctly, its signature is verified, and an expired or foreign token is rejected.
 */
class JwtServiceTest {

	private static final String SECRET = "unit-test-signing-key-0123456789-abcdefghij";
	private static final String OTHER_SECRET = "a-completely-different-key-0123456789-abcdef";
	/**
	 * Anchored to real time, not a literal instant: {@code NimbusJwtDecoder} validates expiry
	 * against the system clock, so a fixed date would make these tests pass or fail depending on
	 * when they are run.
	 */
	private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);
	private static final Duration ACCESS_TOKEN_EXPIRATION = Duration.ofMinutes(15);

	@Test
	void accessTokenCarriesTheUserIdUsernameAndPermissionAuthorities() {
		Jwt decoded = serviceAt(NOW).verify(serviceAt(NOW).generateAccessToken(admin()));

		Object userId = decoded.getClaim(JwtService.CLAIM_USER_ID);
		assertThat(decoded.getSubject()).isEqualTo("admin");
		assertThat(userId).isInstanceOf(Number.class);
		assertThat(((Number) userId).longValue()).isEqualTo(42L);
		// Permission names, not role names: section 4 authorizes on permissions.
		assertThat(decoded.getClaimAsStringList(JwtService.CLAIM_AUTHORITIES))
				.containsExactly("ACCOUNT_READ", "USER_READ");
	}

	@Test
	void accessTokenExpiresAfterTheConfiguredLifetimeNotAHardCodedOne() {
		Jwt decoded = serviceAt(NOW).verify(serviceAt(NOW).generateAccessToken(admin()));

		assertThat(decoded.getIssuedAt()).isEqualTo(NOW);
		assertThat(decoded.getExpiresAt()).isEqualTo(NOW.plus(ACCESS_TOKEN_EXPIRATION));
	}

	@Test
	void accessTokenNeverCarriesThePasswordHash() {
		User admin = admin();

		String token = serviceAt(NOW).generateAccessToken(admin);

		// Checked on the raw token: a JWT payload is signed, not encrypted, so anything in the
		// claims is readable by whoever holds the token.
		assertThat(decodePayload(token)).doesNotContain(admin.getPasswordHash(), "password");
		assertThat(serviceAt(NOW).verify(token).getClaims()).doesNotContainKeys("password", "passwordHash");
	}

	@Test
	void tokenSignedWithAnotherSecretIsRejected() {
		String forged = service(OTHER_SECRET, NOW).generateAccessToken(admin());

		assertThatThrownBy(() -> serviceAt(NOW).verify(forged))
				.isInstanceOf(JwtException.class);
	}

	@Test
	void expiredTokenIsRejected() {
		// Issued long enough in the past that the decoder's default clock skew cannot save it.
		String stale = serviceAt(NOW.minus(Duration.ofHours(2))).generateAccessToken(admin());

		assertThatThrownBy(() -> serviceAt(NOW).verify(stale))
				.isInstanceOf(JwtException.class);
	}

	@Test
	void malformedTokenIsRejected() {
		assertThatThrownBy(() -> serviceAt(NOW).verify("not-a-jwt"))
				.isInstanceOf(JwtException.class);
	}

	@Test
	void startupFailsWithAnActionableMessageWhenTheSecretIsMissing() {
		// This is the whole point of having no default for JWT_SECRET: running with a weak or
		// absent key must be impossible, not merely discouraged.
		assertThatThrownBy(() -> JwtService.signingKey(""))
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("JWT_SECRET")
				.hasMessageContaining(".env");

		assertThatThrownBy(() -> JwtService.signingKey(null))
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("JWT_SECRET");
	}

	@Test
	void startupFailsWhenTheSecretIsShorterThanHs256Requires() {
		String tooShort = "x".repeat(JwtService.MINIMUM_SECRET_LENGTH - 1);

		assertThatThrownBy(() -> JwtService.signingKey(tooShort))
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("too short")
				.hasMessageContaining(String.valueOf(JwtService.MINIMUM_SECRET_LENGTH));
	}

	@Test
	void secretOfExactlyTheMinimumLengthIsAccepted() {
		assertThat(JwtService.signingKey("y".repeat(JwtService.MINIMUM_SECRET_LENGTH))).isNotNull();
	}

	private static JwtService serviceAt(Instant instant) {
		return service(SECRET, instant);
	}

	private static JwtService service(String secret, Instant instant) {
		JwtProperties properties = new JwtProperties(secret, ACCESS_TOKEN_EXPIRATION, Duration.ofDays(7));
		return new JwtService(properties, Clock.fixed(instant, ZoneOffset.UTC));
	}

	private static User admin() {
		Role role = new Role("ROLE_ADMIN");
		role.addPermission(new Permission("USER_READ"));
		role.addPermission(new Permission("ACCOUNT_READ"));
		User user = new User("admin", "$2a$10$notARealHashButShapedLikeOneAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
		user.addRole(role);
		// The id is database-generated, so a detached test fixture has to be given one.
		ReflectionTestUtils.setField(user, "id", 42L);
		return user;
	}

	private static String decodePayload(String token) {
		String[] parts = token.split("\\.");
		return new String(java.util.Base64.getUrlDecoder().decode(parts[1]), java.nio.charset.StandardCharsets.UTF_8);
	}
}
