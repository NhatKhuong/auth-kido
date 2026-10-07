package com.example.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

/**
 * The static UI of backlog 0009 against the real security chain (architecture 01-overview.md
 * section 11), including the {@code /password.html} page split out of {@code account.html} by
 * backlog 0011.
 *
 * <p>Two claims are made here and they pull in opposite directions, which is the whole point of
 * testing them in one class: the pages must load for a browser that holds no token yet, and the
 * rule that allows that must not have opened the API. A {@code permitAll} is easy to write one
 * pattern too wide, and a widened pattern fails silently — every test of the endpoints still
 * passes because they are all written with a token.
 *
 * <p>Each refusal is paired with a positive control that differs in one variable, so a 401 or a
 * 403 cannot be mistaken for a typo in the path or a broken token.
 *
 * <p>What is not asserted here: that the browser hides the admin link from an account without
 * {@code USER_READ}, or the password link from one without {@code PASSWORD_CHANGE}. Those are
 * decisions taken by JavaScript after {@code GET /api/users/me} answers, and MockMvc runs no
 * JavaScript — they were observed in a browser instead (see the ticket's Evidence). The
 * server-side half of those rules, the 403 itself, is covered by
 * {@code RbacAuthorizationIntegrationTest}.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
class StaticUiIntegrationTest {

	private static final String ADMIN_PASSWORD = "admin12345";

	@Autowired
	private MockMvc mockMvc;

	/**
	 * Step 5 of the ticket: the pages are readable with no {@code Authorization} header at all.
	 *
	 * <p>This is the one thing the UI cannot work without: a browser arrives at login.html before
	 * it has any way of holding a token.
	 */
	@ParameterizedTest
	@ValueSource(strings = { "/login.html", "/account.html", "/admin.html", "/password.html" })
	void pagesAreServedToAnonymousBrowsers(String path) throws Exception {
		mockMvc.perform(get(path))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML));
	}

	/** The shared script and stylesheet are fetched by those same anonymous page loads. */
	@ParameterizedTest
	@ValueSource(strings = { "/js/api.js", "/css/ui.css" })
	void assetsAreServedToAnonymousBrowsers(String path) throws Exception {
		mockMvc.perform(get(path)).andExpect(status().isOk());
	}

	/**
	 * The pages carry no data and no credentials.
	 *
	 * <p>What makes serving them anonymously safe is that they are empty shells: everything a user
	 * sees is fetched afterwards by an authenticated call. A page that inlined a username, a seed
	 * password or a signing key would turn this {@code permitAll} into a leak.
	 */
	@ParameterizedTest
	@ValueSource(strings = {
			"/login.html", "/account.html", "/admin.html", "/password.html", "/js/api.js" })
	void pagesContainNoCredentialsOrSeededData(String path) throws Exception {
		String body = mockMvc.perform(get(path))
				.andReturn()
				.getResponse()
				.getContentAsString(StandardCharsets.UTF_8);

		assertThat(body)
				.doesNotContain(ADMIN_PASSWORD, "user12345")
				.doesNotContain("$2a$")
				.doesNotContain("test-only-signing-key");
	}

	/**
	 * The other half: {@code /api/**} is still 401 without a token.
	 *
	 * <p>Every endpoint of 0006 and 0007, so the rule is checked on the paths the UI calls rather
	 * than on one sample. {@code POST /api/auth/login} is excluded on purpose — it is public by
	 * design and the UI could not log in otherwise.
	 */
	@Test
	void apiStillRequiresATokenAfterTheStaticRuleWasAdded() throws Exception {
		mockMvc.perform(get("/api/users/me"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.code").value("UNAUTHORIZED"));

		mockMvc.perform(put("/api/users/me/password")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"currentPassword\":\"a\",\"newPassword\":\"bbbbbbbb\"}"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.code").value("UNAUTHORIZED"));

		mockMvc.perform(get("/api/admin/users"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.code").value("UNAUTHORIZED"));

		// Positive control: the same paths answer 200 for the admin token, so the three 401s above
		// are the authentication requirement and not three mistyped routes.
		String token = bearerForAdmin();
		mockMvc.perform(get("/api/users/me").header("Authorization", token))
				.andExpect(status().isOk());
		mockMvc.perform(get("/api/admin/users").header("Authorization", token))
				.andExpect(status().isOk());
	}

	/**
	 * The {@code permitAll} patterns cannot be reached from under {@code /api}.
	 *
	 * <p>{@code "/*.html"} is a single segment at the root, so an API path dressed up to look like
	 * a page is still an API path. If the pattern were ever loosened to {@code "/**&#47;*.html"} or
	 * to a bare {@code "/**"}, these turn from 404 into 200-or-whatever and say so.
	 */
	@ParameterizedTest
	@ValueSource(strings = { "/api/admin/users.html", "/api/users/me.html", "/api/js/api.js" })
	void anApiPathSpelledLikeAStaticFileIsNotPermitted(String path) throws Exception {
		mockMvc.perform(get(path))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
	}

	/**
	 * An unknown static path is 404, not 200.
	 *
	 * <p>Rules out the failure where the UI "works" because something — a forwarding rule, a
	 * catch-all — answers every path, which would make the assertions above meaningless.
	 */
	@Test
	void anUnknownPageIsNotFound() throws Exception {
		mockMvc.perform(get("/no-such-page.html"))
				.andExpect(status().isNotFound())
				.andExpect(jsonPath("$.code").value("NOT_FOUND"));
	}

	/**
	 * Backlog 0011: the password form lives on {@code /password.html} and no longer on
	 * {@code /account.html}.
	 *
	 * <p>Asserted on the served markup because the move is the whole ticket — a page that loads
	 * with 200 would pass every other test here while still holding the form on the wrong page, or
	 * holding it on neither.
	 */
	@Test
	void thePasswordFormMovedToItsOwnPage() throws Exception {
		// The call itself, not a mention of the path: account.html still names the endpoint in a
		// comment explaining which permission gates the link, and that comment is not a request.
		String passwordCall = "Api.request('/api/users/me/password'";

		assertThat(servedBody("/password.html"))
				.contains("id=\"password-form\"", "id=\"current-password\"", "id=\"new-password\"")
				.contains(passwordCall);

		assertThat(servedBody("/account.html"))
				.doesNotContain("id=\"password-form\"", "id=\"current-password\"", "id=\"new-password\"")
				.doesNotContain(passwordCall)
				// The navigation link replacing it is gated on the permission the endpoint
				// requires, not on a role name.
				.contains("href=\"password.html\"")
				.contains("PASSWORD_CHANGE");
	}

	/** Returns the response body of an anonymous {@code GET}, asserting it was served at all. */
	private String servedBody(String path) throws Exception {
		return mockMvc.perform(get(path))
				.andExpect(status().isOk())
				.andReturn()
				.getResponse()
				.getContentAsString(StandardCharsets.UTF_8);
	}

	/** Logs in and returns the {@code Authorization} header value for the issued access token. */
	private String bearerForAdmin() throws Exception {
		String body = mockMvc.perform(post("/api/auth/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"username\":\"admin\",\"password\":\"%s\"}".formatted(ADMIN_PASSWORD)))
				.andExpect(status().isOk())
				.andReturn()
				.getResponse()
				.getContentAsString(StandardCharsets.UTF_8);
		return "Bearer " + JsonPath.parse(body).read("$.accessToken", String.class);
	}
}
