package com.example.auth.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.exception.UnauthorizedException;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import tools.jackson.databind.ObjectMapper;

/**
 * The 403 rendered when the filter chain denies a request (backlog 0007).
 *
 * <p>Tested directly rather than through MockMvc because this is the one path that bypasses the
 * dispatcher entirely: {@code ExceptionTranslationFilter} calls the handler with the raw response,
 * so the status, content type and body are produced here and nowhere else.
 *
 * <p>Jackson 3 ({@code tools.jackson}) is what Boot 4 autoconfigures — ADR 0002.
 */
class JsonAccessDeniedHandlerTest {

	private final JsonAccessDeniedHandler handler = new JsonAccessDeniedHandler(new ObjectMapper());

	@Test
	void deniedRequestGets403WithTheForbiddenCode() throws Exception {
		MockHttpServletResponse response = handle(new AccessDeniedException("Access Denied"));

		assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
		// startsWith, not equals: MockHttpServletResponse appends the charset it was given.
		assertThat(response.getContentType()).startsWith(MediaType.APPLICATION_JSON_VALUE);
		assertThat(response.getCharacterEncoding()).isEqualToIgnoringCase(StandardCharsets.UTF_8.name());
		assertThat(response.getContentAsString(StandardCharsets.UTF_8))
				.isEqualTo("{\"code\":\"FORBIDDEN\",\"message\":\"%s\"}".formatted(JsonAccessDeniedHandler.MESSAGE));
	}

	/** The literal is the contract; a rename here is a contract change, not a refactor. */
	@Test
	void theCodeIsTheForbiddenLiteral() {
		assertThat(JsonAccessDeniedHandler.CODE).isEqualTo("FORBIDDEN");
		// And it is not the 401 code: the two statuses must stay distinguishable by code alone.
		assertThat(JsonAccessDeniedHandler.CODE).isNotEqualTo(UnauthorizedException.CODE);
	}

	@Test
	void theRequiredAuthorityIsNotRevealed() throws Exception {
		// Spring Security's message names the authority that was missing; echoing it would hand a
		// caller the authorization model one denial at a time.
		MockHttpServletResponse response =
				handle(new AuthorizationDeniedException("Access Denied for authority USER_READ"));

		assertThat(response.getContentAsString(StandardCharsets.UTF_8))
				.doesNotContain("USER_READ")
				.doesNotContain("Access Denied for authority");
	}

	@Test
	void theDenialIsSilentAboutTheRequestItRejected() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/admin/users");
		request.addHeader("Authorization", "Bearer a.jwt.value");
		MockHttpServletResponse response = new MockHttpServletResponse();

		handler.handle(request, response, new AccessDeniedException("Access Denied"));

		// A token must never be reflected back, not even inside an error message.
		assertThat(response.getContentAsString(StandardCharsets.UTF_8)).doesNotContain("a.jwt.value");
	}

	private MockHttpServletResponse handle(AccessDeniedException denied) throws Exception {
		MockHttpServletResponse response = new MockHttpServletResponse();
		handler.handle(new MockHttpServletRequest("GET", "/api/admin/users"), response, denied);
		return response;
	}
}
