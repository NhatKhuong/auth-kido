package com.example.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.auth.config.JwtProperties;
import com.example.auth.dto.request.LoginRequest;
import com.example.auth.dto.response.LoginResponse;
import com.example.auth.entity.Permission;
import com.example.auth.entity.RefreshToken;
import com.example.auth.entity.Role;
import com.example.auth.entity.User;
import com.example.auth.exception.InvalidCredentialsException;
import com.example.auth.repository.RefreshTokenRepository;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.JwtService;
import com.example.auth.security.RefreshTokenHasher;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Login business rules of architecture 01-overview.md sections 3 and 9.
 *
 * <p>A real {@link BCryptPasswordEncoder} is used instead of a mock: the point of these tests is
 * that a stored hash actually verifies, which a stubbed encoder would assert nothing about.
 */
@ExtendWith(MockitoExtension.class)
class AuthenticationServiceImplTest {

	private static final Instant NOW = Instant.parse("2026-10-07T10:00:00Z");
	private static final Duration ACCESS_TOKEN_EXPIRATION = Duration.ofMinutes(15);
	private static final Duration REFRESH_TOKEN_EXPIRATION = Duration.ofDays(7);
	private static final String PASSWORD = "user12345";

	@Mock
	private UserRepository userRepository;

	@Mock
	private RefreshTokenRepository refreshTokenRepository;

	@Mock
	private JwtService jwtService;

	private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
	private final RefreshTokenHasher refreshTokenHasher = new RefreshTokenHasher();

	private AuthenticationServiceImpl service;
	private User account;

	@BeforeEach
	void setUp() {
		JwtProperties properties =
				new JwtProperties("ignored-by-the-mocked-jwt-service", ACCESS_TOKEN_EXPIRATION, REFRESH_TOKEN_EXPIRATION);
		service = new AuthenticationServiceImpl(
				userRepository,
				refreshTokenRepository,
				passwordEncoder,
				jwtService,
				refreshTokenHasher,
				properties,
				Clock.fixed(NOW, ZoneOffset.UTC));
		account = user("user", PASSWORD);
	}

	@Test
	void loginReturnsBearerTokensWithExpiresInDerivedFromConfiguration() {
		when(userRepository.findByUsername("user")).thenReturn(Optional.of(account));
		when(jwtService.generateAccessToken(account)).thenReturn("the.access.token");

		LoginResponse response = service.login(new LoginRequest("user", PASSWORD));

		assertThat(response.accessToken()).isEqualTo("the.access.token");
		assertThat(response.tokenType()).isEqualTo("Bearer");
		assertThat(response.refreshToken()).isNotBlank();
		// Derived from the 15m Duration, not a literal 900 anywhere in the code.
		assertThat(response.expiresIn()).isEqualTo(ACCESS_TOKEN_EXPIRATION.toSeconds());
	}

	@Test
	void loginStoresOnlyTheHashOfTheRefreshTokenItReturns() {
		when(userRepository.findByUsername("user")).thenReturn(Optional.of(account));
		when(jwtService.generateAccessToken(account)).thenReturn("the.access.token");

		LoginResponse response = service.login(new LoginRequest("user", PASSWORD));

		ArgumentCaptor<RefreshToken> saved = ArgumentCaptor.forClass(RefreshToken.class);
		verify(refreshTokenRepository).save(saved.capture());
		RefreshToken stored = saved.getValue();
		assertThat(stored.getTokenHash())
				.isNotEqualTo(response.refreshToken())
				.isEqualTo(refreshTokenHasher.hash(response.refreshToken()));
		assertThat(stored.getUser()).isSameAs(account);
		// created_at has no database default, so the application has to supply it.
		assertThat(stored.getCreatedAt()).isEqualTo(NOW);
		assertThat(stored.getExpiresAt()).isEqualTo(NOW.plus(REFRESH_TOKEN_EXPIRATION));
	}

	@Test
	void loginIsRejectedWhenThePasswordIsWrong() {
		when(userRepository.findByUsername("user")).thenReturn(Optional.of(account));

		assertThatThrownBy(() -> service.login(new LoginRequest("user", "wrong-password")))
				.isInstanceOf(InvalidCredentialsException.class)
				.hasFieldOrPropertyWithValue("code", InvalidCredentialsException.CODE)
				.hasFieldOrPropertyWithValue("status", HttpStatus.UNAUTHORIZED);

		verify(refreshTokenRepository, never()).save(any());
	}

	@Test
	void loginIsRejectedTheSameWayWhenTheUsernameDoesNotExist() {
		when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());

		// Same exception, same code, same 401 as a wrong password: the response must not reveal
		// whether the account exists, and it must not be a 404.
		assertThatThrownBy(() -> service.login(new LoginRequest("ghost", PASSWORD)))
				.isInstanceOf(InvalidCredentialsException.class)
				.hasFieldOrPropertyWithValue("code", InvalidCredentialsException.CODE)
				.hasFieldOrPropertyWithValue("status", HttpStatus.UNAUTHORIZED);

		verify(refreshTokenRepository, never()).save(any());
	}

	@Test
	void loginNeverEchoesThePasswordBackToTheCaller() {
		when(userRepository.findByUsername("user")).thenReturn(Optional.of(account));
		when(jwtService.generateAccessToken(account)).thenReturn("the.access.token");

		LoginResponse response = service.login(new LoginRequest("user", PASSWORD));

		assertThat(response.toString()).doesNotContain(PASSWORD);
		assertThat(response.accessToken()).doesNotContain(PASSWORD);
		assertThat(response.refreshToken()).doesNotContain(PASSWORD);
	}

	@Test
	void requestObjectDoesNotPrintThePasswordWhenLoggedOrPutInAnExceptionMessage() {
		assertThat(new LoginRequest("user", PASSWORD).toString())
				.contains("user")
				.doesNotContain(PASSWORD);
	}

	private User user(String username, String plaintextPassword) {
		Role role = new Role("ROLE_USER");
		role.addPermission(new Permission("ACCOUNT_READ"));
		role.addPermission(new Permission("PASSWORD_CHANGE"));
		User created = new User(username, passwordEncoder.encode(plaintextPassword));
		created.addRole(role);
		ReflectionTestUtils.setField(created, "id", 7L);
		return created;
	}
}
