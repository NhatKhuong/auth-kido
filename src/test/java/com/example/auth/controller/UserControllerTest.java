package com.example.auth.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.hamcrest.Matchers.contains;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auth.dto.request.ChangePasswordRequest;
import com.example.auth.dto.response.AccountResponse;
import com.example.auth.exception.InvalidCurrentPasswordException;
import com.example.auth.security.AuthenticatedUser;
import com.example.auth.security.JsonAuthenticationEntryPoint;
import com.example.auth.security.JwtAuthenticationFilter;
import com.example.auth.security.JwtService;
import com.example.auth.service.UserService;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * HTTP contract of {@code GET /api/users/me} and {@code PUT /api/users/me/password} (backlog 0006),
 * as a slice: status codes and response shape without a database.
 *
 * <p>Boot 4 package coordinates for the slice annotations come from ADR 0002, and the recipe is the
 * one {@code AuthControllerTest} documents: {@code addFilters = false} (a slice does not load
 * {@code SecurityConfig}, so Boot's default CSRF-protected chain would answer every write here with
 * 403), the entry point imported and {@link JwtService} mocked because a slice still instantiates
 * {@link JwtAuthenticationFilter}.
 *
 * <p>With the filters off, nothing populates the {@code SecurityContext}, so the principal is put
 * there directly — that is all {@code @AuthenticationPrincipal} reads. {@code @PreAuthorize} is
 * inert in a slice for the same reason {@code SecurityConfig} is absent; the permission checks are
 * proved end to end by {@code AccountAndPasswordIntegrationTest}.
 */
@WebMvcTest(UserController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(JsonAuthenticationEntryPoint.class)
class UserControllerTest {

	private static final long USER_ID = 7L;
	private static final String PASSWORD_PATH = "/api/users/me/password";

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private UserService userService;

	@MockitoBean
	private JwtService jwtService;

	@BeforeEach
	void authenticate() {
		SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
				new AuthenticatedUser(USER_ID, "user"),
				null,
				List.of(new SimpleGrantedAuthority("ACCOUNT_READ"), new SimpleGrantedAuthority("PASSWORD_CHANGE"))));
	}

	@AfterEach
	void clearAuthentication() {
		SecurityContextHolder.clearContext();
	}

	@Test
	void currentAccountReturns200WithTheContractedBody() throws Exception {
		when(userService.getCurrentAccount(USER_ID)).thenReturn(new AccountResponse(
				USER_ID, "user", List.of("ROLE_USER"), List.of("ACCOUNT_READ", "PASSWORD_CHANGE")));

		mockMvc.perform(get("/api/users/me"))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.id").value(USER_ID))
				.andExpect(jsonPath("$.username").value("user"))
				// Hamcrest, not value(List): the order is part of the contract, and a matcher reads
				// the JSON array itself instead of going through a type conversion.
				.andExpect(jsonPath("$.roles", contains("ROLE_USER")))
				.andExpect(jsonPath("$.permissions", contains("ACCOUNT_READ", "PASSWORD_CHANGE")))
				// The closed field set of the contract: nothing else may appear.
				.andExpect(jsonPath("$.password").doesNotExist())
				.andExpect(jsonPath("$.passwordHash").doesNotExist())
				.andExpect(jsonPath("$.refreshToken").doesNotExist())
				.andExpect(jsonPath("$.tokenHash").doesNotExist());
	}

	@Test
	void currentAccountIsReadForTheAuthenticatedPrincipalOnly() throws Exception {
		when(userService.getCurrentAccount(USER_ID))
				.thenReturn(new AccountResponse(USER_ID, "user", List.of(), List.of()));

		mockMvc.perform(get("/api/users/me").param("userId", "1")).andExpect(status().isOk());

		// "me" must mean the token's subject: a request parameter cannot redirect the lookup.
		verify(userService).getCurrentAccount(USER_ID);
	}

	@Test
	void changePasswordReturns204WithAnEmptyBody() throws Exception {
		String body = mockMvc.perform(put(PASSWORD_PATH)
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"currentPassword\":\"user12345\",\"newPassword\":\"new-password-1\"}"))
				.andExpect(status().isNoContent())
				.andReturn()
				.getResponse()
				.getContentAsString();

		assertThat(body).isEmpty();
		verify(userService).changePassword(USER_ID, new ChangePasswordRequest("user12345", "new-password-1"));
	}

	@Test
	void wrongCurrentPasswordReturns400WithTheInvalidCurrentPasswordCode() throws Exception {
		doThrow(new InvalidCurrentPasswordException())
				.when(userService).changePassword(eq(USER_ID), any());

		String body = mockMvc.perform(put(PASSWORD_PATH)
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"currentPassword\":\"wrong-one\",\"newPassword\":\"new-password-1\"}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("INVALID_CURRENT_PASSWORD"))
				.andExpect(jsonPath("$.message").isNotEmpty())
				.andReturn()
				.getResponse()
				.getContentAsString();

		// The rejection must not quote back either password it was given.
		assertThat(body).doesNotContain("wrong-one", "new-password-1");
	}

	@Test
	void missingCurrentPasswordReturns400AndNeverReachesTheService() throws Exception {
		mockMvc.perform(put(PASSWORD_PATH)
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"newPassword\":\"new-password-1\"}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));

		verify(userService, never()).changePassword(any(), any());
	}

	@Test
	void missingNewPasswordReturns400AndNeverReachesTheService() throws Exception {
		mockMvc.perform(put(PASSWORD_PATH)
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"currentPassword\":\"user12345\"}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));

		verifyNoInteractions(userService);
	}

	@Test
	void tooShortNewPasswordReturns400WithTheSharedValidationCode() throws Exception {
		mockMvc.perform(put(PASSWORD_PATH)
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"currentPassword\":\"user12345\",\"newPassword\":\"short\"}"))
				.andExpect(status().isBadRequest())
				// A length rule is ordinary input validation, not a new error code.
				.andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));

		verifyNoInteractions(userService);
	}

	@Test
	void blankNewPasswordReturns400() throws Exception {
		mockMvc.perform(put(PASSWORD_PATH)
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"currentPassword\":\"user12345\",\"newPassword\":\"          \"}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));

		verifyNoInteractions(userService);
	}

	@Test
	void malformedBodyReturns400WithoutEchoingEitherPassword() throws Exception {
		String body = mockMvc.perform(put(PASSWORD_PATH)
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"currentPassword\":\"user12345\",\"newPassword\":\"new-password-1\""))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("MALFORMED_REQUEST"))
				.andReturn()
				.getResponse()
				.getContentAsString();

		assertThat(body).doesNotContain("user12345", "new-password-1");
		verifyNoInteractions(userService);
	}

	@Test
	void aValidationFailureNeverQuotesTheSubmittedPassword() throws Exception {
		String body = mockMvc.perform(put(PASSWORD_PATH)
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"currentPassword\":\"user12345\",\"newPassword\":\"tiny\"}"))
				.andExpect(status().isBadRequest())
				.andReturn()
				.getResponse()
				.getContentAsString();

		// Bean validation messages name the field; the rejected value must stay out of them.
		assertThat(body).doesNotContain("user12345", "tiny");
	}
}
