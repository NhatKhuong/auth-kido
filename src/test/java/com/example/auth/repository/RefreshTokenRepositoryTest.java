package com.example.auth.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.entity.RefreshToken;
import com.example.auth.entity.User;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;

/**
 * Checks the refresh token mapping against the real table, since the refresh flow in backlog
 * 0005 resolves a token purely by its hash.
 */
@DataJpaOnPostgres
class RefreshTokenRepositoryTest {

	private static final String TOKEN_HASH = "3b1f8a0e2c4d6f8a0b2c4d6e8f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2";

	@Autowired
	private RefreshTokenRepository refreshTokenRepository;

	@Autowired
	private UserRepository userRepository;

	@Test
	void storesAndResolvesATokenByItsHash() {
		User user = requireUser("user");
		Instant createdAt = Instant.now().truncatedTo(ChronoUnit.MILLIS);
		Instant expiresAt = createdAt.plus(7, ChronoUnit.DAYS);

		refreshTokenRepository.saveAndFlush(new RefreshToken(user, TOKEN_HASH, expiresAt, createdAt));

		RefreshToken found = refreshTokenRepository.findByTokenHash(TOKEN_HASH).orElseThrow();
		assertThat(found.getId()).isNotNull();
		assertThat(found.getUser().getId()).isEqualTo(user.getId());
		assertThat(found.getExpiresAt()).isEqualTo(expiresAt);
		assertThat(found.getCreatedAt()).isEqualTo(createdAt);
	}

	@Test
	void returnsEmptyForAnUnknownHash() {
		assertThat(refreshTokenRepository.findByTokenHash("no-such-hash")).isEmpty();
	}

	/**
	 * The unique constraint is what stops one stored hash from ever resolving to two users, which
	 * would make the refresh endpoint hand out an access token for the wrong account.
	 */
	@Test
	void rejectsTwoTokensWithTheSameHash() {
		Instant now = Instant.now();
		refreshTokenRepository.saveAndFlush(
				new RefreshToken(requireUser("user"), TOKEN_HASH, now.plus(7, ChronoUnit.DAYS), now));

		RefreshToken duplicate =
				new RefreshToken(requireUser("admin"), TOKEN_HASH, now.plus(7, ChronoUnit.DAYS), now);

		assertThatThrownBy(() -> refreshTokenRepository.saveAndFlush(duplicate))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	private User requireUser(String username) {
		return userRepository.findByUsername(username).orElseThrow();
	}
}
