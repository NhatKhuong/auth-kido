package com.example.auth.repository;

import com.example.auth.entity.RefreshToken;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

	/**
	 * The refresh flow hashes the token it receives and looks the hash up here; the plaintext token
	 * is never stored, so this is the only way to resolve one.
	 */
	Optional<RefreshToken> findByTokenHash(String tokenHash);
}
