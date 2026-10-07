package com.example.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.auth.config.JwtProperties;
import com.example.auth.entity.RefreshToken;
import com.example.auth.entity.User;
import com.example.auth.repository.RefreshTokenRepository;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.JwtService;
import com.example.auth.security.RefreshTokenHasher;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;

/**
 * End-to-end authentication against the real security chain, the real migrations and the real
 * seeded accounts (architecture 01-overview.md section 9).
 *
 * <p>These are the cases a mocked test cannot prove: that the configured BCrypt encoder really
 * verifies the hashes migration V7 seeded, that the stored refresh token is a hash of the one
 * handed to the client, that refresh really deletes the presented row and inserts a replacement
 * (ADR 0003), and that an unauthenticated request is answered by our entry point rather than by
 * Spring Security's defaults.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
class AuthenticationFlowIntegrationTest {

	/** Requires authentication; the handler behind it arrives in backlog 0006. */
	private static final String PROTECTED_PATH = "/api/users/me";

	private static final String REFRESH_PATH = "/api/auth/refresh";

	private static final String ADMIN_PASSWORD = "admin12345";
	private static final String USER_PASSWORD = "user12345";

	/**
	 * The application's own hasher, used to read the stored rows the way the service writes them.
	 * It holds no state beyond a {@code SecureRandom}, so a plain instance is equivalent to the bean.
	 */
	private static final RefreshTokenHasher HASHER = new RefreshTokenHasher();

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private RefreshTokenRepository refreshTokenRepository;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private JwtProperties jwtProperties;

	@Test
	void seededAdminCanLogInAndGetsTheContractedBody() throws Exception {
		String body = loginBody("admin", ADMIN_PASSWORD, status().isOk());
		DocumentContext json = JsonPath.parse(body);

		assertThat(json.read("$.accessToken", String.class)).isNotBlank();
		assertThat(json.read("$.refreshToken", String.class)).isNotBlank();
		assertThat(json.read("$.tokenType", String.class)).isEqualTo("Bearer");
		assertThat(json.read("$.expiresIn", Long.class))
				.isEqualTo(jwtProperties.accessTokenExpiration().toSeconds());
		// Nothing about the credential may appear in the response (section 7).
		assertThat(body).doesNotContain(ADMIN_PASSWORD, "password", "passwordHash", "tokenHash");
	}

	@Test
	void seededUserCanLogIn() throws Exception {
		DocumentContext json = JsonPath.parse(loginBody("user", USER_PASSWORD, status().isOk()));

		assertThat(json.read("$.accessToken", String.class)).isNotBlank();
		assertThat(json.read("$.tokenType", String.class)).isEqualTo("Bearer");
		assertThat(json.read("$.expiresIn", Long.class))
				.isEqualTo(jwtProperties.accessTokenExpiration().toSeconds());
	}

	@Test
	void accessTokenCarriesPermissionsAndNothingSensitive() throws Exception {
		String token = accessToken("admin", ADMIN_PASSWORD);

		String payload = payloadOf(token);
		DocumentContext claims = JsonPath.parse(payload);
		assertThat(claims.read("$.sub", String.class)).isEqualTo("admin");
		assertThat(claims.read("$.uid", Long.class)).isPositive();
		List<String> authorities = ((List<?>) claims.read("$.authorities", List.class)).stream()
				.map(String::valueOf)
				.toList();
		assertThat(authorities)
				.containsExactlyInAnyOrder("ACCOUNT_READ", "PASSWORD_CHANGE", "USER_READ", "USER_MANAGE");
		assertThat(Instant.ofEpochSecond(claims.read("$.exp", Long.class)))
				.isAfter(Instant.now())
				.isBefore(Instant.now().plus(jwtProperties.accessTokenExpiration()).plusSeconds(10));
		// "$2a$" is the BCrypt prefix: the stored hash must not have travelled into the token.
		assertThat(payload).doesNotContain("$2a$", ADMIN_PASSWORD, "passwordHash", "password");
	}

	@Test
	void refreshTokenIsPersistedOnlyAsAHash() throws Exception {
		String issued = JsonPath.parse(loginBody("user", USER_PASSWORD, status().isOk()))
				.read("$.refreshToken", String.class);

		RefreshToken stored = refreshTokenRepository
				.findByTokenHash(new RefreshTokenHasher().hash(issued))
				.orElseThrow();
		assertThat(stored.getTokenHash()).isNotEqualTo(issued);
		// The id is read off the lazy proxy, which needs no session: the row belongs to "user".
		assertThat(stored.getUser().getId())
				.isEqualTo(userRepository.findByUsername("user").orElseThrow().getId());
		// created_at has no database default, so the application must have supplied it.
		assertThat(stored.getCreatedAt()).isNotNull();
		assertThat(stored.getExpiresAt()).isAfter(stored.getCreatedAt());
		assertThat(refreshTokenRepository.findAll())
				.extracting(RefreshToken::getTokenHash)
				.doesNotContain(issued);
	}

	@Test
	void wrongPasswordIsRejectedWith401InvalidCredentials() throws Exception {
		DocumentContext json =
				JsonPath.parse(loginBody("admin", "definitely-not-the-password", status().isUnauthorized()));

		assertThat(json.read("$.code", String.class)).isEqualTo("INVALID_CREDENTIALS");
		assertThat(json.read("$.message", String.class)).isNotBlank();
	}

	@Test
	void unknownUsernameIsRejectedWithTheSame401AndNotA404() throws Exception {
		DocumentContext json =
				JsonPath.parse(loginBody("no-such-account", ADMIN_PASSWORD, status().isUnauthorized()));

		// Identical to a wrong password: the API must not disclose which usernames exist.
		assertThat(json.read("$.code", String.class)).isEqualTo("INVALID_CREDENTIALS");
	}

	@Test
	void incompleteBodyIsA400NotA401() throws Exception {
		mockMvc.perform(post("/api/auth/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"username\":\"admin\"}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));
	}

	@Test
	void protectedPathWithoutATokenIs401Json() throws Exception {
		mockMvc.perform(get(PROTECTED_PATH))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string("WWW-Authenticate", "Bearer"))
				.andExpect(jsonPath("$.code").value("UNAUTHORIZED"))
				.andExpect(jsonPath("$.message").isNotEmpty());
	}

	@Test
	void protectedPathWithATokenSignedByAnotherKeyIs401() throws Exception {
		String forged = tokenSignedWith("a-different-key-than-the-application-uses", Instant.now());

		mockMvc.perform(get(PROTECTED_PATH).header("Authorization", "Bearer " + forged))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
	}

	@Test
	void protectedPathWithAnExpiredTokenIs401() throws Exception {
		String expired = tokenSignedWith(jwtProperties.secret(), Instant.now().minus(Duration.ofHours(2)));

		mockMvc.perform(get(PROTECTED_PATH).header("Authorization", "Bearer " + expired))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
	}

	@Test
	void protectedPathWithAGarbageTokenIs401() throws Exception {
		mockMvc.perform(get(PROTECTED_PATH).header("Authorization", "Bearer not-a-token"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
	}

	@Test
	void aValidTokenGetsPastAuthentication() throws Exception {
		String token = accessToken("admin", ADMIN_PASSWORD);

		// 404, not 401: the token was accepted and the request reached dispatch. The handler is
		// backlog 0006, so the assertion is "no longer unauthenticated", not a success body.
		mockMvc.perform(get(PROTECTED_PATH).header("Authorization", "Bearer " + token))
				.andExpect(status().isNotFound());
	}

	@Test
	void refreshTokenCannotBeUsedAsAnAccessToken() throws Exception {
		String refreshToken = JsonPath.parse(loginBody("user", USER_PASSWORD, status().isOk()))
				.read("$.refreshToken", String.class);

		// A refresh token is an opaque random value, not a JWT, so it cannot authenticate anything
		// (section 3: it must never reach a business API).
		mockMvc.perform(get(PROTECTED_PATH).header("Authorization", "Bearer " + refreshToken))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
	}

	@Test
	void passwordNeverReachesTheLogOnEitherASuccessfulOrAFailedLogin() throws Exception {
		Logger root = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
		Logger application = (Logger) LoggerFactory.getLogger("com.example.auth");
		ListAppender<ILoggingEvent> captured = new ListAppender<>();
		captured.setContext((LoggerContext) LoggerFactory.getILoggerFactory());
		captured.start();
		Level originalLevel = application.getLevel();
		// TRACE, so a debug statement that happened to print the request object would be caught.
		application.setLevel(Level.TRACE);
		root.addAppender(captured);
		try {
			loginBody("admin", ADMIN_PASSWORD, status().isOk());
			loginBody("admin", "a-wrong-password-value", status().isUnauthorized());
		}
		finally {
			root.detachAppender(captured);
			application.setLevel(originalLevel);
			captured.stop();
		}

		assertThat(captured.list).isNotEmpty();
		assertThat(captured.list).allSatisfy(event -> assertThat(event.getFormattedMessage())
				.doesNotContain(ADMIN_PASSWORD)
				.doesNotContain("a-wrong-password-value"));
	}

	@Test
	void refreshExchangesAValidTokenForNewTokensAndRotatesTheStoredRow() throws Exception {
		String issued = refreshTokenFromLogin("user", USER_PASSWORD);
		String issuedHash = HASHER.hash(issued);
		long userId = userRepository.findByUsername("user").orElseThrow().getId();
		assertThat(refreshTokenRepository.findByTokenHash(issuedHash)).isPresent();

		String body = refreshBody(issued, status().isOk());
		DocumentContext json = JsonPath.parse(body);

		assertThat(json.read("$.accessToken", String.class)).isNotBlank();
		assertThat(json.read("$.tokenType", String.class)).isEqualTo("Bearer");
		assertThat(json.read("$.expiresIn", Long.class))
				.isEqualTo(jwtProperties.accessTokenExpiration().toSeconds());
		String rotated = json.read("$.refreshToken", String.class);
		assertThat(rotated).isNotBlank().isNotEqualTo(issued);
		assertThat(body).doesNotContain("password", "passwordHash", "tokenHash", issuedHash);

		// ADR 0003 at the database level: the presented row is gone and a new one has taken its
		// place for the same user. This is the assertion the whole rotation decision rests on.
		assertThat(refreshTokenRepository.findByTokenHash(issuedHash)).isEmpty();
		RefreshToken replacement = refreshTokenRepository.findByTokenHash(HASHER.hash(rotated)).orElseThrow();
		assertThat(replacement.getUser().getId()).isEqualTo(userId);
		assertThat(replacement.getExpiresAt()).isAfter(replacement.getCreatedAt());
		// Still only a hash: the plaintext replacement was never written down either.
		assertThat(refreshTokenRepository.findAll())
				.extracting(RefreshToken::getTokenHash)
				.doesNotContain(rotated, issued);
	}

	@Test
	void theAccessTokenReturnedByRefreshAuthenticatesARequest() throws Exception {
		String refreshed = JsonPath.parse(refreshBody(refreshTokenFromLogin("admin", ADMIN_PASSWORD), status().isOk()))
				.read("$.accessToken", String.class);

		// 404, not 401: the freshly minted token was accepted and the request reached dispatch.
		// Identity against the login token is deliberately not asserted — two tokens minted for
		// the same user inside the same second are byte-identical by construction, so such an
		// assertion would be flaky and would prove nothing about usability.
		mockMvc.perform(get(PROTECTED_PATH).header("Authorization", "Bearer " + refreshed))
				.andExpect(status().isNotFound());
	}

	@Test
	void aRotatedRefreshTokenIsRejectedOnItsSecondUse() throws Exception {
		String issued = refreshTokenFromLogin("user", USER_PASSWORD);
		refreshBody(issued, status().isOk());

		// Single use (ADR 0003): replaying the token a second time must fail, which is what makes
		// a stolen copy usable at most once and a replay observable to the real user.
		DocumentContext json = JsonPath.parse(refreshBody(issued, status().isUnauthorized()));
		assertThat(json.read("$.code", String.class)).isEqualTo("INVALID_REFRESH_TOKEN");
	}

	@Test
	void anUnknownRefreshTokenIsRejectedWith401() throws Exception {
		DocumentContext json = JsonPath.parse(
				refreshBody("a-token-that-was-never-issued", status().isUnauthorized()));

		assertThat(json.read("$.code", String.class)).isEqualTo("INVALID_REFRESH_TOKEN");
		assertThat(json.read("$.message", String.class)).isNotBlank();
	}

	@Test
	void anExpiredRefreshTokenIsRejectedWith401() throws Exception {
		String expired = HASHER.generateToken();
		Instant createdAt = Instant.now().minus(Duration.ofDays(8));
		refreshTokenRepository.saveAndFlush(new RefreshToken(
				userRepository.findByUsername("user").orElseThrow(),
				HASHER.hash(expired),
				createdAt.plus(jwtProperties.refreshTokenExpiration()),
				createdAt));

		DocumentContext json = JsonPath.parse(refreshBody(expired, status().isUnauthorized()));

		// Same code as an unknown token: the client must not learn which of the two it was.
		assertThat(json.read("$.code", String.class)).isEqualTo("INVALID_REFRESH_TOKEN");
		// An expired token must not have been rotated into a live one.
		assertThat(refreshTokenRepository.findByTokenHash(HASHER.hash(expired))).isPresent();
	}

	@Test
	void aMalformedRefreshTokenIsRejectedWithTheSame401AndNotA500() throws Exception {
		// Refresh tokens are opaque, so there is no format to validate; a value of any shape
		// hashes to something and lands in the same "unknown token" branch.
		DocumentContext json = JsonPath.parse(refreshBody("}{ not base64url %%", status().isUnauthorized()));

		assertThat(json.read("$.code", String.class)).isEqualTo("INVALID_REFRESH_TOKEN");
	}

	@Test
	void refreshWithAnIncompleteBodyIsA400NotA401() throws Exception {
		mockMvc.perform(post(REFRESH_PATH).contentType(MediaType.APPLICATION_JSON).content("{}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));
	}

	@Test
	void theRefreshTokenReturnedByRefreshStillCannotBeUsedAsAnAccessToken() throws Exception {
		String rotated = JsonPath.parse(refreshBody(refreshTokenFromLogin("user", USER_PASSWORD), status().isOk()))
				.read("$.refreshToken", String.class);

		// Section 3: a refresh token is only ever accepted at /api/auth/refresh, and rotation must
		// not have introduced a token that behaves differently from the one login issues.
		mockMvc.perform(get(PROTECTED_PATH).header("Authorization", "Bearer " + rotated))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
	}

	@Test
	void refreshTokenValuesNeverReachTheLog() throws Exception {
		String issued = refreshTokenFromLogin("user", USER_PASSWORD);
		Logger root = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
		Logger application = (Logger) LoggerFactory.getLogger("com.example.auth");
		ListAppender<ILoggingEvent> captured = new ListAppender<>();
		captured.setContext((LoggerContext) LoggerFactory.getILoggerFactory());
		captured.start();
		Level originalLevel = application.getLevel();
		application.setLevel(Level.TRACE);
		root.addAppender(captured);
		String rotated;
		try {
			rotated = JsonPath.parse(refreshBody(issued, status().isOk())).read("$.refreshToken", String.class);
			refreshBody("a-token-that-was-never-issued", status().isUnauthorized());
		}
		finally {
			root.detachAppender(captured);
			application.setLevel(originalLevel);
			captured.stop();
		}

		assertThat(captured.list).isNotEmpty();
		// The hash is withheld too: it is the lookup key, so it is as good as the token itself.
		assertThat(captured.list).allSatisfy(event -> assertThat(event.getFormattedMessage())
				.doesNotContain(issued)
				.doesNotContain(HASHER.hash(issued))
				.doesNotContain("a-token-that-was-never-issued"));
		assertThat(captured.list).allSatisfy(event -> assertThat(event.getFormattedMessage())
				.doesNotContain(rotated));
	}

	private String accessToken(String username, String password) throws Exception {
		return JsonPath.parse(loginBody(username, password, status().isOk()))
				.read("$.accessToken", String.class);
	}

	private String refreshTokenFromLogin(String username, String password) throws Exception {
		return JsonPath.parse(loginBody(username, password, status().isOk()))
				.read("$.refreshToken", String.class);
	}

	private String refreshBody(String refreshToken, ResultMatcher expectedStatus) throws Exception {
		String request = "{\"refreshToken\":\"%s\"}".formatted(
				refreshToken.replace("\\", "\\\\").replace("\"", "\\\""));
		return mockMvc.perform(post(REFRESH_PATH)
						.contentType(MediaType.APPLICATION_JSON)
						.content(request))
				.andExpect(expectedStatus)
				.andReturn()
				.getResponse()
				.getContentAsString(StandardCharsets.UTF_8);
	}

	private String loginBody(String username, String password, ResultMatcher expectedStatus) throws Exception {
		String request = "{\"username\":\"%s\",\"password\":\"%s\"}".formatted(username, password);
		return mockMvc.perform(post("/api/auth/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content(request))
				.andExpect(expectedStatus)
				.andReturn()
				.getResponse()
				.getContentAsString(StandardCharsets.UTF_8);
	}

	/**
	 * Mints a token with the application's own encoder but a different key or a different "now",
	 * which is how a wrong signature and an expired token are produced without hand-rolling JWS.
	 */
	private String tokenSignedWith(String secret, Instant issuedAt) {
		JwtProperties properties = new JwtProperties(
				secret, jwtProperties.accessTokenExpiration(), jwtProperties.refreshTokenExpiration());
		User admin = userRepository.findByUsername("admin").orElseThrow();
		return new JwtService(properties, Clock.fixed(issuedAt, ZoneOffset.UTC)).generateAccessToken(admin);
	}

	private static String payloadOf(String jwt) {
		return new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8);
	}
}
