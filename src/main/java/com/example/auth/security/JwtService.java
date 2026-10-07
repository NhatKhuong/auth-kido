package com.example.auth.security;

import com.example.auth.config.JwtProperties;
import com.example.auth.entity.Permission;
import com.example.auth.entity.User;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.stereotype.Service;

/**
 * Issues and verifies access tokens (architecture 01-overview.md section 3).
 *
 * <p>The token carries only what the security layer needs to build an {@code Authentication}:
 * the user id, the username and the permission names. Nothing else — in particular never the
 * password hash — because a JWT payload is only signed, not encrypted, and anyone holding the
 * token can read it.
 *
 * <p>Authorities are permission names, not role names: endpoints check a permission
 * (section 4), so a new role becomes effective without changing any endpoint.
 */
@Service
public class JwtService {

	/** Claim holding the user's database id, so a request needs no lookup by username. */
	static final String CLAIM_USER_ID = "uid";

	/** Claim holding the permission names that become granted authorities. */
	static final String CLAIM_AUTHORITIES = "authorities";

	/**
	 * HS256 derives a 256-bit MAC key, so a shorter secret weakens the signature no matter how
	 * the rest of the system behaves. Nimbus itself refuses keys below this length, but failing
	 * here turns a per-request error into a startup error with an actionable message.
	 */
	static final int MINIMUM_SECRET_LENGTH = 32;

	private static final MacAlgorithm ALGORITHM = MacAlgorithm.HS256;

	/** JCA name for the key material behind {@link MacAlgorithm#HS256} (whose own name is "HS256"). */
	private static final String KEY_ALGORITHM = "HmacSHA256";

	private final JwtEncoder encoder;
	private final JwtDecoder decoder;
	private final JwtProperties properties;
	private final Clock clock;

	public JwtService(JwtProperties properties, Clock clock) {
		SecretKey key = signingKey(properties.secret());
		this.encoder = new NimbusJwtEncoder(new ImmutableSecret<>(key));
		// Builds in the default validators, which include expiry; an expired token therefore
		// fails verification here rather than relying on a check somewhere downstream.
		this.decoder = NimbusJwtDecoder.withSecretKey(key).macAlgorithm(ALGORITHM).build();
		this.properties = properties;
		this.clock = clock;
	}

	/**
	 * Fails startup rather than letting the application serve tokens nobody can trust.
	 *
	 * <p>An unset {@code JWT_SECRET} is not a configuration detail: every token the application
	 * would issue is forgeable, and the failure is invisible until someone audits it. Reporting
	 * it at boot, with the fix in the message, is the only safe behaviour.
	 */
	static SecretKey signingKey(String secret) {
		String value = secret == null ? "" : secret;
		if (value.isBlank()) {
			throw new IllegalStateException(
					"JWT_SECRET is not configured, so access tokens cannot be signed. "
							+ "Copy .env.example to .env in projects/api and set JWT_SECRET to at least "
							+ MINIMUM_SECRET_LENGTH + " characters (for example: openssl rand -base64 48).");
		}
		byte[] keyBytes = value.getBytes(StandardCharsets.UTF_8);
		if (keyBytes.length < MINIMUM_SECRET_LENGTH) {
			throw new IllegalStateException(
					"JWT_SECRET is too short: " + keyBytes.length + " bytes, but HS256 needs at least "
							+ MINIMUM_SECRET_LENGTH + ". Set JWT_SECRET in projects/api/.env to a longer "
							+ "random value (for example: openssl rand -base64 48).");
		}
		return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
	}

	/** Mints a signed access token for the given, already authenticated, user. */
	public String generateAccessToken(User user) {
		Instant issuedAt = clock.instant();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.subject(user.getUsername())
				.issuedAt(issuedAt)
				.expiresAt(issuedAt.plus(properties.accessTokenExpiration()))
				.claim(CLAIM_USER_ID, user.getId())
				.claim(CLAIM_AUTHORITIES, authorityNames(user))
				.build();
		JwsHeader header = JwsHeader.with(ALGORITHM).build();
		return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
	}

	/**
	 * Verifies signature and expiry and returns the decoded token.
	 *
	 * @throws JwtException if the token is malformed, signed with another key, or expired
	 */
	public Jwt verify(String token) {
		return decoder.decode(token);
	}

	/** Sorted so a token's payload is stable for the same user and diffable in evidence. */
	private static List<String> authorityNames(User user) {
		return user.getPermissions().stream()
				.map(Permission::getName)
				.sorted(Comparator.naturalOrder())
				.toList();
	}
}
