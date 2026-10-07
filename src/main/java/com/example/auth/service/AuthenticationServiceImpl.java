package com.example.auth.service;

import com.example.auth.config.JwtProperties;
import com.example.auth.dto.request.LoginRequest;
import com.example.auth.dto.response.LoginResponse;
import com.example.auth.entity.RefreshToken;
import com.example.auth.entity.User;
import com.example.auth.exception.InvalidCredentialsException;
import com.example.auth.repository.RefreshTokenRepository;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.JwtService;
import com.example.auth.security.RefreshTokenHasher;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Login flow of architecture 01-overview.md section 3: find the user, check the password with the
 * {@code PasswordEncoder}, mint an access token, issue a refresh token and store only its hash.
 */
@Service
public class AuthenticationServiceImpl implements AuthenticationService {

	private static final Logger log = LoggerFactory.getLogger(AuthenticationServiceImpl.class);

	private final UserRepository userRepository;
	private final RefreshTokenRepository refreshTokenRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final RefreshTokenHasher refreshTokenHasher;
	private final JwtProperties jwtProperties;
	private final Clock clock;

	/**
	 * Hash of a value nobody knows, used only to spend the same time verifying a password for an
	 * account that does not exist as for one that does. Without it, a missing username would answer
	 * measurably faster than a wrong password and the 401 would still leak which usernames exist.
	 */
	private final String absentAccountHash;

	public AuthenticationServiceImpl(
			UserRepository userRepository,
			RefreshTokenRepository refreshTokenRepository,
			PasswordEncoder passwordEncoder,
			JwtService jwtService,
			RefreshTokenHasher refreshTokenHasher,
			JwtProperties jwtProperties,
			Clock clock) {
		this.userRepository = userRepository;
		this.refreshTokenRepository = refreshTokenRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
		this.refreshTokenHasher = refreshTokenHasher;
		this.jwtProperties = jwtProperties;
		this.clock = clock;
		this.absentAccountHash = passwordEncoder.encode(UUID.randomUUID().toString());
	}

	@Override
	@Transactional
	public LoginResponse login(LoginRequest request) {
		Optional<User> account = userRepository.findByUsername(request.username());
		String storedHash = account.map(User::getPasswordHash).orElse(absentAccountHash);
		boolean passwordMatches = passwordEncoder.matches(request.password(), storedHash);

		if (account.isEmpty() || !passwordMatches) {
			// Username only: the attempted password must never reach a log file.
			log.info("Rejected login for username '{}'", request.username());
			throw new InvalidCredentialsException();
		}

		User user = account.get();
		Instant now = clock.instant();
		String refreshToken = refreshTokenHasher.generateToken();
		refreshTokenRepository.save(new RefreshToken(
				user,
				// Only the hash is persisted, so a database dump cannot be replayed as a token.
				refreshTokenHasher.hash(refreshToken),
				now.plus(jwtProperties.refreshTokenExpiration()),
				now));

		log.info("Issued tokens for username '{}'", user.getUsername());
		return LoginResponse.bearer(
				jwtService.generateAccessToken(user),
				refreshToken,
				jwtProperties.accessTokenExpiration());
	}
}
