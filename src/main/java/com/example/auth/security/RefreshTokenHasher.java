package com.example.auth.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import org.springframework.stereotype.Component;

/**
 * Creates refresh tokens and reduces them to the value stored in {@code refresh_tokens.token_hash}
 * (architecture 01-overview.md section 3).
 *
 * <p>Generation and hashing live together on purpose: the hash is only as safe as the entropy of
 * what it digests, so the two decisions must not be able to drift apart.
 *
 * <p><b>Why SHA-256 and not BCrypt.</b> {@code POST /api/auth/refresh} has to find a token by its
 * hash, which requires the hash of a given token to always be the same value; BCrypt mixes in a
 * fresh random salt per call, so the same token hashes differently every time and could never be
 * looked up. BCrypt's cost exists to slow down guessing of <em>human-chosen</em> secrets. A
 * refresh token is not one: it is {@value #TOKEN_BYTES} bytes straight from a CSPRNG, so there is
 * no dictionary to try and brute force over a 256-bit space is not a threat a work factor
 * protects against. What the hash must do here is make a leaked database row unusable as a live
 * token, and a one-way digest of a high-entropy value does exactly that.
 */
@Component
public class RefreshTokenHasher {

	/** 256 bits of entropy: the property the "SHA-256 is enough" argument above depends on. */
	static final int TOKEN_BYTES = 32;

	private static final String DIGEST_ALGORITHM = "SHA-256";

	private final SecureRandom secureRandom = new SecureRandom();

	/** A fresh refresh token, in a form that is safe inside a JSON body and a URL. */
	public String generateToken() {
		byte[] value = new byte[TOKEN_BYTES];
		secureRandom.nextBytes(value);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
	}

	/** The deterministic lookup value for a token; 64 hex characters, well inside VARCHAR(255). */
	public String hash(String token) {
		try {
			byte[] digest = MessageDigest.getInstance(DIGEST_ALGORITHM)
					.digest(token.getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(digest);
		}
		catch (NoSuchAlgorithmException ex) {
			// SHA-256 is required of every Java platform, so this cannot happen at runtime; it is
			// rethrown rather than swallowed so a broken JVM is not mistaken for a bad token.
			throw new IllegalStateException(DIGEST_ALGORITHM + " is not available", ex);
		}
	}
}
