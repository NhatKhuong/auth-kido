package com.example.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.auth.entity.Role;
import com.example.auth.entity.User;
import com.example.auth.repository.RoleRepository;
import com.example.auth.repository.UserRepository;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;

/**
 * {@code GET /api/users/me} and {@code PUT /api/users/me/password} end to end (backlog 0006):
 * real security chain, real migrations, real BCrypt, real database.
 *
 * <p>These are the claims a slice cannot make: that the permission on each endpoint is actually
 * enforced, that the new password is stored as a BCrypt hash different from the old one, and that
 * logging in with the new password works afterwards while the old one stops working.
 *
 * <p>The password tests act on an account this class creates and deletes rather than on the seeded
 * {@code user}: Spring reuses one context — and therefore one database — across test classes, so
 * changing a seeded password here would break {@code AuthenticationFlowIntegrationTest} depending
 * on which class ran first.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
class AccountAndPasswordIntegrationTest {

	private static final String ACCOUNT_PATH = "/api/users/me";
	private static final String PASSWORD_PATH = "/api/users/me/password";

	private static final String FIXTURE_USERNAME = "password-change-fixture";
	private static final String INITIAL_PASSWORD = "initial-password-1";
	private static final String NEW_PASSWORD = "replacement-password-2";

	private static final String ADMIN_PASSWORD = "admin12345";

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private RoleRepository roleRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	private String initialHash;

	@BeforeEach
	void createFixtureAccount() {
		userRepository.findByUsername(FIXTURE_USERNAME).ifPresent(userRepository::delete);
		userRepository.flush();
		Role roleUser = roleRepository.findByName("ROLE_USER").orElseThrow();
		User account = new User(FIXTURE_USERNAME, passwordEncoder.encode(INITIAL_PASSWORD));
		account.addRole(roleUser);
		initialHash = userRepository.saveAndFlush(account).getPasswordHash();
	}

	@AfterEach
	void removeFixtureAccount() {
		userRepository.findByUsername(FIXTURE_USERNAME).ifPresent(userRepository::delete);
		userRepository.flush();
	}

	@Test
	void currentAccountReturnsTheSeededAdminWithRolesAndPermissions() throws Exception {
		String body = mockMvc.perform(get(ACCOUNT_PATH).header("Authorization", bearer("admin", ADMIN_PASSWORD)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.username").value("admin"))
				.andExpect(jsonPath("$.roles", contains("ROLE_ADMIN")))
				// Sorted, and exactly the four ACCOUNT/USER permissions migration V6 grants ADMIN.
				.andExpect(jsonPath("$.permissions",
						contains("ACCOUNT_READ", "PASSWORD_CHANGE", "USER_MANAGE", "USER_READ")))
				.andReturn()
				.getResponse()
				.getContentAsString(StandardCharsets.UTF_8);

		DocumentContext json = JsonPath.parse(body);
		assertThat(json.read("$.id", Long.class))
				.isEqualTo(userRepository.findByUsername("admin").orElseThrow().getId());
		// Section 7: the account API never returns any of these. "$2a$" is the BCrypt prefix, so
		// this also catches a hash that leaked under some other field name.
		assertThat(body)
				.doesNotContain("password\"", "passwordHash", "refreshToken", "tokenHash", "$2a$", ADMIN_PASSWORD);
	}

	@Test
	void currentAccountReturnsTheCallersOwnAccountNotTheFirstRow() throws Exception {
		mockMvc.perform(get(ACCOUNT_PATH).header("Authorization", bearer(FIXTURE_USERNAME, INITIAL_PASSWORD)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.username").value(FIXTURE_USERNAME))
				.andExpect(jsonPath("$.roles", contains("ROLE_USER")))
				.andExpect(jsonPath("$.permissions", contains("ACCOUNT_READ", "PASSWORD_CHANGE")));
	}

	@Test
	void currentAccountWithoutATokenIs401Unauthorized() throws Exception {
		mockMvc.perform(get(ACCOUNT_PATH))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string("WWW-Authenticate", "Bearer"))
				.andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
	}

	@Test
	void changePasswordReturns204AndTheNewPasswordIsTheOneThatLogsIn() throws Exception {
		String body = changePassword(
				bearer(FIXTURE_USERNAME, INITIAL_PASSWORD), INITIAL_PASSWORD, NEW_PASSWORD, status().isNoContent());

		// 204 means no body at all, so nothing can have been echoed.
		assertThat(body).isEmpty();
		// The whole point of the endpoint: the new credential works and the old one does not.
		loginBody(FIXTURE_USERNAME, NEW_PASSWORD, status().isOk());
		DocumentContext rejected =
				JsonPath.parse(loginBody(FIXTURE_USERNAME, INITIAL_PASSWORD, status().isUnauthorized()));
		assertThat(rejected.read("$.code", String.class)).isEqualTo("INVALID_CREDENTIALS");
	}

	@Test
	void theStoredValueIsANewBcryptHashAndNeverThePlaintext() throws Exception {
		changePassword(
				bearer(FIXTURE_USERNAME, INITIAL_PASSWORD), INITIAL_PASSWORD, NEW_PASSWORD, status().isNoContent());

		String stored = userRepository.findByUsername(FIXTURE_USERNAME).orElseThrow().getPasswordHash();
		assertThat(stored)
				.isNotEqualTo(NEW_PASSWORD)
				.isNotEqualTo(INITIAL_PASSWORD)
				// A new hash, not the old row left untouched.
				.isNotEqualTo(initialHash)
				// BCrypt, verified at the database level rather than inferred from the API working.
				.startsWith("$2a$")
				.hasSize(60);
		assertThat(passwordEncoder.matches(NEW_PASSWORD, stored)).isTrue();
		assertThat(passwordEncoder.matches(INITIAL_PASSWORD, stored)).isFalse();
	}

	@Test
	void aWrongCurrentPasswordIs400InvalidCurrentPasswordAndChangesNothing() throws Exception {
		String body = changePassword(
				bearer(FIXTURE_USERNAME, INITIAL_PASSWORD),
				"not-the-current-password",
				NEW_PASSWORD,
				status().isBadRequest());

		DocumentContext json = JsonPath.parse(body);
		assertThat(json.read("$.code", String.class)).isEqualTo("INVALID_CURRENT_PASSWORD");
		assertThat(json.read("$.message", String.class)).isNotBlank();
		assertThat(body).doesNotContain("not-the-current-password", NEW_PASSWORD, "$2a$");

		// Unchanged in the database, and the original password still logs in.
		assertThat(userRepository.findByUsername(FIXTURE_USERNAME).orElseThrow().getPasswordHash())
				.isEqualTo(initialHash);
		loginBody(FIXTURE_USERNAME, INITIAL_PASSWORD, status().isOk());
		loginBody(FIXTURE_USERNAME, NEW_PASSWORD, status().isUnauthorized());
	}

	@Test
	void anIncompleteBodyIs400ValidationErrorAndChangesNothing() throws Exception {
		mockMvc.perform(put(PASSWORD_PATH)
						.header("Authorization", bearer(FIXTURE_USERNAME, INITIAL_PASSWORD))
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"currentPassword\":\"%s\"}".formatted(INITIAL_PASSWORD)))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));

		assertThat(userRepository.findByUsername(FIXTURE_USERNAME).orElseThrow().getPasswordHash())
				.isEqualTo(initialHash);
	}

	@Test
	void changePasswordWithoutATokenIs401Unauthorized() throws Exception {
		mockMvc.perform(put(PASSWORD_PATH)
						.contentType(MediaType.APPLICATION_JSON)
						.content(changePasswordBody(INITIAL_PASSWORD, NEW_PASSWORD)))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string("WWW-Authenticate", "Bearer"))
				.andExpect(jsonPath("$.code").value("UNAUTHORIZED"));

		// A 401 must be decided before the body is read, so nothing changed.
		assertThat(userRepository.findByUsername(FIXTURE_USERNAME).orElseThrow().getPasswordHash())
				.isEqualTo(initialHash);
	}

	@Test
	void changePasswordWithARefreshTokenInsteadOfAnAccessTokenIs401() throws Exception {
		String refreshToken = JsonPath.parse(loginBody(FIXTURE_USERNAME, INITIAL_PASSWORD, status().isOk()))
				.read("$.refreshToken", String.class);

		// Section 3: a refresh token must never reach a business API.
		mockMvc.perform(put(PASSWORD_PATH)
						.header("Authorization", "Bearer " + refreshToken)
						.contentType(MediaType.APPLICATION_JSON)
						.content(changePasswordBody(INITIAL_PASSWORD, NEW_PASSWORD)))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
	}

	@Test
	void noPasswordValueReachesTheLogOnEitherASuccessfulOrARejectedChange() throws Exception {
		String authorization = bearer(FIXTURE_USERNAME, INITIAL_PASSWORD);
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
			changePassword(authorization, "a-wrong-current-password", NEW_PASSWORD, status().isBadRequest());
			changePassword(authorization, INITIAL_PASSWORD, NEW_PASSWORD, status().isNoContent());
			loginBody(FIXTURE_USERNAME, NEW_PASSWORD, status().isOk());
		}
		finally {
			root.detachAppender(captured);
			application.setLevel(originalLevel);
			captured.stop();
		}

		assertThat(captured.list).isNotEmpty();
		assertThat(captured.list).allSatisfy(event -> assertThat(event.getFormattedMessage())
				.doesNotContain(INITIAL_PASSWORD)
				.doesNotContain(NEW_PASSWORD)
				.doesNotContain("a-wrong-current-password")
				// The stored hash is a credential-equivalent too: it must not be logged either.
				.doesNotContain(initialHash));
	}

	private String changePassword(
			String authorization,
			String currentPassword,
			String newPassword,
			ResultMatcher expectedStatus) throws Exception {
		return mockMvc.perform(put(PASSWORD_PATH)
						.header("Authorization", authorization)
						.contentType(MediaType.APPLICATION_JSON)
						.content(changePasswordBody(currentPassword, newPassword)))
				.andExpect(expectedStatus)
				.andReturn()
				.getResponse()
				.getContentAsString(StandardCharsets.UTF_8);
	}

	private static String changePasswordBody(String currentPassword, String newPassword) {
		return "{\"currentPassword\":\"%s\",\"newPassword\":\"%s\"}".formatted(currentPassword, newPassword);
	}

	/** Logs in and returns the {@code Authorization} header value for the issued access token. */
	private String bearer(String username, String password) throws Exception {
		return "Bearer " + JsonPath.parse(loginBody(username, password, status().isOk()))
				.read("$.accessToken", String.class);
	}

	private String loginBody(String username, String password, ResultMatcher expectedStatus) throws Exception {
		return mockMvc.perform(post("/api/auth/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"username\":\"%s\",\"password\":\"%s\"}".formatted(username, password)))
				.andExpect(expectedStatus)
				.andReturn()
				.getResponse()
				.getContentAsString(StandardCharsets.UTF_8);
	}
}
