package com.example.auth.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * The two properties the refresh token design depends on: the hash is deterministic (otherwise
 * {@code /api/auth/refresh} could never find a stored token) and the generated token is unique and
 * unguessable (otherwise a deterministic, unsalted hash would not be safe).
 */
class RefreshTokenHasherTest {

	private final RefreshTokenHasher hasher = new RefreshTokenHasher();

	@Test
	void hashIsDeterministicSoAStoredTokenCanBeLookedUp() {
		String token = hasher.generateToken();

		assertThat(hasher.hash(token)).isEqualTo(hasher.hash(token));
		assertThat(new RefreshTokenHasher().hash(token)).isEqualTo(hasher.hash(token));
	}

	@Test
	void hashDoesNotRevealTheToken() {
		String token = hasher.generateToken();

		String hash = hasher.hash(token);

		assertThat(hash).isNotEqualTo(token).doesNotContain(token);
		// 64 hex characters, which must stay inside refresh_tokens.token_hash VARCHAR(255).
		assertThat(hash).hasSize(64).matches("[0-9a-f]{64}");
	}

	@Test
	void differentTokensHashDifferently() {
		assertThat(hasher.hash("token-a")).isNotEqualTo(hasher.hash("token-b"));
	}

	@Test
	void generatedTokensAreDistinctAndCarryTheExpectedEntropy() {
		Set<String> tokens = new HashSet<>();
		for (int i = 0; i < 500; i++) {
			tokens.add(hasher.generateToken());
		}

		assertThat(tokens).hasSize(500);
		// 32 random bytes, base64url without padding.
		assertThat(tokens).allSatisfy(token -> assertThat(token).hasSize(43).matches("[A-Za-z0-9_-]{43}"));
	}
}
