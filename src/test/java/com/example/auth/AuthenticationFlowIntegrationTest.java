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
 * handed to the client, and that an unauthenticated request is answered by our entry point rather
 * than by Spring Security's defaults.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
class AuthenticationFlowIntegrationTest {

	/** Requires authentication; the handler behind it arrives in backlog 0006. */
	private static final String PROTECTED_PATH = "/api/users/me";

	private static final String ADMIN_PASSWORD = "admin12345";
	private static final String USER_PASSWORD = "user12345";

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

	private String accessToken(String username, String password) throws Exception {
		return JsonPath.parse(loginBody(username, password, status().isOk()))
				.read("$.accessToken", String.class);
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
