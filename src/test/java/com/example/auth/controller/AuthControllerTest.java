package com.example.auth.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auth.dto.request.LoginRequest;
import com.example.auth.dto.request.RefreshTokenRequest;
import com.example.auth.dto.response.LoginResponse;
import com.example.auth.exception.InvalidCredentialsException;
import com.example.auth.exception.InvalidRefreshTokenException;
import com.example.auth.security.JsonAuthenticationEntryPoint;
import com.example.auth.security.JwtAuthenticationFilter;
import com.example.auth.security.JwtService;
import com.example.auth.service.AuthenticationService;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * HTTP contract of {@code POST /api/auth/login} and {@code POST /api/auth/refresh} (architecture
 * 01-overview.md section 7), as a slice: status codes and response shape without a database or
 * real tokens.
 *
 * <p>{@code @WebMvcTest} on Spring Boot 4 lives in {@code org.springframework.boot.webmvc.test.autoconfigure}
 * (ADR 0002).
 *
 * <p>{@code addFilters = false} removes the servlet filters, including Spring Security's. A slice
 * does not load the application's {@code SecurityConfig}, so what would run instead is Boot's
 * default chain — CSRF-protected, answering every POST here with 403 and saying nothing about this
 * controller. The real chain is exercised end to end by {@code AuthenticationFlowIntegrationTest}.
 *
 * <p>{@link JwtAuthenticationFilter} is still instantiated, because a slice does include
 * {@code Filter} beans, so its two collaborators have to be present: the entry point is imported
 * and {@link JwtService} is mocked (no signing key is needed when no token is verified).
 */
@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(JsonAuthenticationEntryPoint.class)
class AuthControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private AuthenticationService authenticationService;

	@MockitoBean
	private JwtService jwtService;

	@Test
	void validCredentialsReturn200WithTheContractedBody() throws Exception {
		when(authenticationService.login(new LoginRequest("admin", "admin12345")))
				.thenReturn(LoginResponse.bearer("access-token", "refresh-token", Duration.ofMinutes(15)));

		mockMvc.perform(post("/api/auth/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"username\":\"admin\",\"password\":\"admin12345\"}"))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.accessToken").value("access-token"))
				.andExpect(jsonPath("$.refreshToken").value("refresh-token"))
				.andExpect(jsonPath("$.tokenType").value("Bearer"))
				.andExpect(jsonPath("$.expiresIn").value(900));
	}

	@Test
	void rejectedCredentialsReturn401WithTheInvalidCredentialsCode() throws Exception {
		when(authenticationService.login(any())).thenThrow(new InvalidCredentialsException());

		mockMvc.perform(post("/api/auth/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"username\":\"admin\",\"password\":\"wrong\"}"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"))
				.andExpect(jsonPath("$.message").isNotEmpty());
	}

	@Test
	void missingPasswordFieldReturns400AndNeverReachesTheService() throws Exception {
		mockMvc.perform(post("/api/auth/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"username\":\"admin\"}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));

		verify(authenticationService, never()).login(any());
	}

	@Test
	void blankUsernameReturns400() throws Exception {
		mockMvc.perform(post("/api/auth/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"username\":\"  \",\"password\":\"admin12345\"}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));

		verify(authenticationService, never()).login(any());
	}

	@Test
	void malformedBodyReturns400WithoutEchoingThePayload() throws Exception {
		String response = mockMvc.perform(post("/api/auth/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"username\":\"admin\",\"password\":\"admin12345\""))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("MALFORMED_REQUEST"))
				.andReturn()
				.getResponse()
				.getContentAsString();

		// A parse error must not quote the body back: the body contains a password.
		org.assertj.core.api.Assertions.assertThat(response).doesNotContain("admin12345");
	}

	@Test
	void validRefreshTokenReturns200WithTheSameBodyShapeAsLogin() throws Exception {
		when(authenticationService.refresh(new RefreshTokenRequest("the-stored-refresh-token")))
				.thenReturn(LoginResponse.bearer("new-access-token", "new-refresh-token", Duration.ofMinutes(15)));

		mockMvc.perform(post("/api/auth/refresh")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"refreshToken\":\"the-stored-refresh-token\"}"))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.accessToken").value("new-access-token"))
				// Rotation (ADR 0003): the replacement token is part of the 200 body.
				.andExpect(jsonPath("$.refreshToken").value("new-refresh-token"))
				.andExpect(jsonPath("$.tokenType").value("Bearer"))
				.andExpect(jsonPath("$.expiresIn").value(900));
	}

	@Test
	void rejectedRefreshTokenReturns401WithTheSingleInvalidRefreshTokenCode() throws Exception {
		when(authenticationService.refresh(any())).thenThrow(new InvalidRefreshTokenException());

		mockMvc.perform(post("/api/auth/refresh")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"refreshToken\":\"no-such-token\"}"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.code").value("INVALID_REFRESH_TOKEN"))
				.andExpect(jsonPath("$.message").isNotEmpty());
	}

	@Test
	void missingRefreshTokenFieldReturns400AndNeverReachesTheService() throws Exception {
		mockMvc.perform(post("/api/auth/refresh")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));

		// A 400, not a 401: the request never reached the point where a token could be judged.
		verify(authenticationService, never()).refresh(any());
	}

	@Test
	void blankRefreshTokenReturns400() throws Exception {
		mockMvc.perform(post("/api/auth/refresh")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"refreshToken\":\"   \"}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));

		verify(authenticationService, never()).refresh(any());
	}

	@Test
	void malformedRefreshBodyReturns400WithoutEchoingTheToken() throws Exception {
		String response = mockMvc.perform(post("/api/auth/refresh")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"refreshToken\":\"a-real-refresh-token\""))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("MALFORMED_REQUEST"))
				.andReturn()
				.getResponse()
				.getContentAsString();

		// A refresh token is credential-equivalent, so a parse error must not quote it back.
		org.assertj.core.api.Assertions.assertThat(response).doesNotContain("a-real-refresh-token");
	}
}
