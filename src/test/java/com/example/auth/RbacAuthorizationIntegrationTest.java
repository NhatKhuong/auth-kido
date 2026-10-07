package com.example.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;

/**
 * RBAC end to end (backlog 0007, architecture 01-overview.md section 9 "Authorization"): the real
 * security chain, real migrations, real tokens, real database.
 *
 * <p>These are the claims a slice cannot make. {@code @PreAuthorize} is inert in a
 * {@code @WebMvcTest}, so "USER is actually refused {@code /api/admin/users}" can only be proved
 * with the application context up.
 *
 * <p>Each rejection is paired with a positive control that differs in exactly one variable, because
 * a 403 or a 401 on its own proves nothing — a typo in the path produces both:
 * <ul>
 *   <li>the token that is refused the admin list is accepted at {@code /api/users/me}, so the 403
 *       is about the missing permission and not about a broken token;</li>
 *   <li>the admin token is accepted at the same path, so the 403 is a real authorization decision
 *       and not a 404 wearing a different status.</li>
 * </ul>
 *
 * <p>Nothing here grants, revokes or edits anything: the seeded accounts of migration V7 are only
 * read, so this class is safe to run in any order against the context Spring shares across test
 * classes.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
class RbacAuthorizationIntegrationTest {

	private static final String ADMIN_USERS_PATH = "/api/admin/users";
	private static final String ACCOUNT_PATH = "/api/users/me";

	private static final String ADMIN_PASSWORD = "admin12345";
	private static final String USER_PASSWORD = "user12345";

	@Autowired
	private MockMvc mockMvc;

	/** Section 9: "USER truy cập endpoint được phép → 200". The control for the 403 below. */
	@Test
	void userReachesItsOwnAccount() throws Exception {
		mockMvc.perform(get(ACCOUNT_PATH).header("Authorization", bearer("user", USER_PASSWORD)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.username").value("user"))
				// ROLE_USER holds neither USER_READ nor USER_MANAGE (migration V6). This is the
				// reason the next test gets a 403, asserted rather than assumed.
				.andExpect(jsonPath("$.permissions", contains("ACCOUNT_READ", "PASSWORD_CHANGE")));
	}

	/** Section 9: "USER truy cập endpoint yêu cầu permission của ADMIN → 403". */
	@Test
	void userIsRefusedTheAdminListWithTheForbiddenCode() throws Exception {
		String token = bearer("user", USER_PASSWORD);

		String body = mockMvc.perform(get(ADMIN_USERS_PATH).header("Authorization", token))
				.andExpect(status().isForbidden())
				.andExpect(jsonPath("$.code").value("FORBIDDEN"))
				.andExpect(jsonPath("$.message").isNotEmpty())
				.andReturn()
				.getResponse()
				.getContentAsString(StandardCharsets.UTF_8);

		// Same token, different endpoint: 200. So the token authenticates fine and the 403 is the
		// missing USER_READ, not a rejected credential — which would have been a 401 anyway.
		mockMvc.perform(get(ACCOUNT_PATH).header("Authorization", token)).andExpect(status().isOk());

		// The denial names neither the permission it wanted nor the token it was given.
		assertThat(body)
				.doesNotContain("USER_READ", "USER_MANAGE")
				.doesNotContain(token.substring("Bearer ".length()))
				.doesNotContain("$2a$");
	}

	/** Section 9: "ADMIN truy cập endpoint quản trị → 200". */
	@Test
	void adminReadsTheUserListWithRolesAndWithoutCredentials() throws Exception {
		String body = mockMvc.perform(get(ADMIN_USERS_PATH)
						.header("Authorization", bearer("admin", ADMIN_PASSWORD)))
				.andExpect(status().isOk())
				// Both seeded accounts are present; the list is not filtered to the caller.
				.andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(2))))
				.andReturn()
				.getResponse()
				.getContentAsString(StandardCharsets.UTF_8);

		DocumentContext json = JsonPath.parse(body);
		List<Map<String, Object>> entries = json.read("$");
		assertThat(entries).extracting(entry -> entry.get("username")).contains("admin", "user");
		// Role names come from the real user_roles rows of migration V7, so this asserts the join
		// is actually mapped and not that a constant was echoed.
		assertThat(rolesOf(entries, "admin")).containsExactly("ROLE_ADMIN");
		assertThat(rolesOf(entries, "user")).containsExactly("ROLE_USER");

		// The closed field set of the contract (section 7): exactly these three keys on every
		// entry. A column added to the entity later cannot appear without failing here.
		assertThat(entries).allSatisfy(entry ->
				assertThat(entry.keySet()).containsExactlyInAnyOrder("id", "username", "roles"));
		assertThat(body)
				.doesNotContain("passwordHash", "refreshToken", "tokenHash", "permissions")
				.doesNotContain("$2a$", ADMIN_PASSWORD, USER_PASSWORD);
	}

	/** Section 9: "không token → 401". */
	@Test
	void anAnonymousCallerGets401NotForbidden() throws Exception {
		mockMvc.perform(get(ADMIN_USERS_PATH))
				.andExpect(status().isUnauthorized())
				// 401, not 403: the caller has not identified itself, so the code must say
				// UNAUTHORIZED. The two are different literals on purpose.
				.andExpect(jsonPath("$.code").value("UNAUTHORIZED"));

		// The route exists and answers 200 for a permitted caller, so the 401 above is the
		// authentication requirement and not a missing endpoint.
		mockMvc.perform(get(ADMIN_USERS_PATH).header("Authorization", bearer("admin", ADMIN_PASSWORD)))
				.andExpect(status().isOk());
	}

	/**
	 * A token that is present but unusable is 401, not 403.
	 *
	 * <p>Keeps the two codes from blurring: "I cannot tell who you are" and "you are not allowed"
	 * are different answers and a client acts differently on them — refresh versus give up.
	 */
	@Test
	void anInvalidTokenGets401NotForbidden() throws Exception {
		mockMvc.perform(get(ADMIN_USERS_PATH).header("Authorization", "Bearer not-a-jwt"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
	}

	/**
	 * A refresh token cannot be used as an access token on the admin endpoint either.
	 *
	 * <p>Section 3 says a refresh token is only usable at {@code POST /api/auth/refresh}; 0007 adds
	 * a new protected route, so the rule has to hold there too.
	 */
	@Test
	void aRefreshTokenIsNotAnAccessTokenForTheAdminList() throws Exception {
		String refreshToken = JsonPath.parse(loginBody("admin", ADMIN_PASSWORD, status().isOk()))
				.read("$.refreshToken", String.class);

		mockMvc.perform(get(ADMIN_USERS_PATH).header("Authorization", "Bearer " + refreshToken))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
	}

	@SuppressWarnings("unchecked")
	private static List<String> rolesOf(List<Map<String, Object>> entries, String username) {
		return entries.stream()
				.filter(entry -> username.equals(entry.get("username")))
				.map(entry -> (List<String>) entry.get("roles"))
				.findFirst()
				.orElseThrow(() -> new AssertionError("no entry for username " + username));
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
