package com.example.auth.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auth.dto.response.UserSummaryResponse;
import com.example.auth.security.AuthenticatedUser;
import com.example.auth.security.JsonAccessDeniedHandler;
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
 * HTTP contract of {@code GET /api/admin/users} (backlog 0007) as a slice: status code and the
 * closed field set of the response, without a database.
 *
 * <p>Boot 4 package coordinates for the slice annotations come from ADR 0002, and the recipe is the
 * one {@code UserControllerTest} documents: {@code addFilters = false} because a slice does not
 * load {@code SecurityConfig}, {@link JwtService} mocked because a slice still instantiates
 * {@link JwtAuthenticationFilter}, and the principal put into the {@code SecurityContext} by hand
 * because nothing populates it with the filters off.
 *
 * <p>{@code @PreAuthorize} is inert in a slice for the same reason {@code SecurityConfig} is
 * absent, so the 403 and 401 branches are not provable here: those are asserted end to end by
 * {@code RbacAuthorizationIntegrationTest}. {@link JsonAccessDeniedHandler} is imported only so the
 * context matches the application's, mirroring the entry point import.
 */
@WebMvcTest(AdminUserController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import({ JsonAuthenticationEntryPoint.class, JsonAccessDeniedHandler.class })
class AdminUserControllerTest {

	private static final String ADMIN_USERS_PATH = "/api/admin/users";

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private UserService userService;

	@MockitoBean
	private JwtService jwtService;

	@BeforeEach
	void authenticate() {
		SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
				new AuthenticatedUser(1L, "admin"),
				null,
				List.of(new SimpleGrantedAuthority("USER_READ"))));
	}

	@AfterEach
	void clearAuthentication() {
		SecurityContextHolder.clearContext();
	}

	@Test
	void listReturns200WithTheContractedBody() throws Exception {
		when(userService.listUsers()).thenReturn(List.of(
				new UserSummaryResponse(1L, "admin", List.of("ROLE_ADMIN")),
				new UserSummaryResponse(2L, "user", List.of("ROLE_USER"))));

		String body = mockMvc.perform(get(ADMIN_USERS_PATH))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$", hasSize(2)))
				.andExpect(jsonPath("$[0].id").value(1))
				.andExpect(jsonPath("$[0].username").value("admin"))
				// Hamcrest, not value(List): see ADR 0002 — value(List.of(...)) reads back as null
				// on this stack.
				.andExpect(jsonPath("$[0].roles", contains("ROLE_ADMIN")))
				.andExpect(jsonPath("$[1].username").value("user"))
				.andExpect(jsonPath("$[1].roles", contains("ROLE_USER")))
				// The closed field set of the contract: id, username, roles and nothing else.
				.andExpect(jsonPath("$[0].password").doesNotExist())
				.andExpect(jsonPath("$[0].passwordHash").doesNotExist())
				.andExpect(jsonPath("$[0].permissions").doesNotExist())
				.andExpect(jsonPath("$[0].refreshToken").doesNotExist())
				.andExpect(jsonPath("$[0].tokenHash").doesNotExist())
				.andReturn()
				.getResponse()
				.getContentAsString();

		// "$2a$" is the BCrypt prefix, so this also catches a hash leaked under another name.
		assertThat(body).doesNotContain("$2a$");
	}

	@Test
	void anEmptyDatabaseStillReturns200WithAnEmptyArray() throws Exception {
		when(userService.listUsers()).thenReturn(List.of());

		// An empty collection is not an error: 200 with [] keeps the client's parsing uniform.
		mockMvc.perform(get(ADMIN_USERS_PATH))
				.andExpect(status().isOk())
				.andExpect(content().json("[]"));
	}
}
