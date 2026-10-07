package com.example.auth.exception;

import com.example.auth.dto.response.ErrorResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import com.example.auth.security.JsonAccessDeniedHandler;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The status/code mapping asserted here is the API contract from
 * {@code documents/architecture/01-overview.md} section 7.
 */
class GlobalExceptionHandlerTest {

	private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

	private final MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new ProbeController())
			.setControllerAdvice(handler)
			.build();

	@Test
	void invalidBodyFieldReturns400WithValidationCode() throws Exception {
		mockMvc.perform(post("/probe/validated")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"username\":\" \"}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("VALIDATION_ERROR"))
				.andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("username")));
	}

	@Test
	void unparsableBodyReturns400WithoutEchoingThePayload() throws Exception {
		mockMvc.perform(post("/probe/validated")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"password\":\"s3cret\""))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("MALFORMED_REQUEST"))
				.andExpect(jsonPath("$.message").value("Request body is missing or malformed"));
	}

	@Test
	void resourceNotFoundReturns404() throws Exception {
		mockMvc.perform(post("/probe/not-found"))
				.andExpect(status().isNotFound())
				.andExpect(jsonPath("$.code").value("NOT_FOUND"))
				.andExpect(jsonPath("$.message").value("User 42 does not exist"));
	}

	/** One code per status: an unmatched route and a missing record must not drift apart. */
	@Test
	void bothKindsOf404ShareOneCode() {
		ResponseEntity<ErrorResponse> unmatchedRoute = handler.handleNoHandler(
				new NoResourceFoundException(org.springframework.http.HttpMethod.GET, "/nope", "nope"));
		ResponseEntity<ErrorResponse> missingRecord =
				handler.handleApiException(new ResourceNotFoundException("User 42 does not exist"));

		assertThat(missingRecord.getBody().code())
				.isEqualTo(unmatchedRoute.getBody().code())
				.isEqualTo("NOT_FOUND");
	}

	@Test
	void conflictReturns409() throws Exception {
		mockMvc.perform(post("/probe/conflict"))
				.andExpect(status().isConflict())
				.andExpect(jsonPath("$.code").value("CONFLICT"))
				.andExpect(jsonPath("$.message").value("Username is already taken"));
	}

	@Test
	void unexpectedFailureReturns500WithoutLeakingDetail() throws Exception {
		mockMvc.perform(post("/probe/boom"))
				.andExpect(status().isInternalServerError())
				.andExpect(jsonPath("$.code").value("INTERNAL_ERROR"))
				.andExpect(jsonPath("$.message").value("An unexpected error occurred"));
	}

	@Test
	void unknownPathReturns404() {
		ResponseEntity<ErrorResponse> response =
				handler.handleNoHandler(
						new NoResourceFoundException(org.springframework.http.HttpMethod.GET, "/nope", "nope"));

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
		assertThat(response.getBody()).isEqualTo(new ErrorResponse("NOT_FOUND", "The requested resource was not found"));
	}

	@Test
	void securityFailuresAreLeftToTheSecurityLayer() {
		AccessDeniedException denied = new AccessDeniedException("denied");

		assertThatThrownBy(() -> handler.handleUnexpected(denied)).isSameAs(denied);
	}

	/**
	 * A {@code @PreAuthorize} denial surfaces during handler invocation, so it arrives here rather
	 * than at the filter chain's access denied handler.
	 */
	@Test
	void methodSecurityDenialReturns403WithTheForbiddenCode() throws Exception {
		String body = mockMvc.perform(post("/probe/denied"))
				.andExpect(status().isForbidden())
				.andExpect(jsonPath("$.code").value("FORBIDDEN"))
				.andExpect(jsonPath("$.message").isNotEmpty())
				.andReturn()
				.getResponse()
				.getContentAsString();

		// Spring Security's message names the missing authority; it must not be echoed.
		assertThat(body).doesNotContain("USER_READ");
	}

	/** Both ways of being denied must be indistinguishable to a client. */
	@Test
	void bothDenialPathsRenderTheSameBody() {
		ResponseEntity<ErrorResponse> fromMethodSecurity = handler.handleAuthorizationDenied(
				new AuthorizationDeniedException("Access Denied for authority USER_READ"));

		assertThat(fromMethodSecurity.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
		// The literals are read from the filter-chain handler, not repeated, so this asserts they
		// are in fact shared.
		assertThat(fromMethodSecurity.getBody())
				.isEqualTo(new ErrorResponse(JsonAccessDeniedHandler.CODE, JsonAccessDeniedHandler.MESSAGE));
		assertThat(fromMethodSecurity.getBody().code()).isEqualTo("FORBIDDEN");
	}

	@Test
	void apiExceptionKeepsItsOwnStatusAndCode() {
		ResponseEntity<ErrorResponse> response =
				handler.handleApiException(new ConflictException("USERNAME_TAKEN", "taken"));

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
		assertThat(response.getBody()).isEqualTo(new ErrorResponse("USERNAME_TAKEN", "taken"));
	}

	@RestController
	static class ProbeController {

		record Payload(@NotBlank String username) {
		}

		@PostMapping("/probe/validated")
		void validated(@Valid @RequestBody Payload payload) {
		}

		@PostMapping("/probe/not-found")
		void notFound() {
			throw new ResourceNotFoundException("User 42 does not exist");
		}

		@PostMapping("/probe/conflict")
		void conflict() {
			throw new ConflictException("Username is already taken");
		}

		@PostMapping("/probe/boom")
		void boom() {
			throw new IllegalStateException("database on fire");
		}

		/**
		 * Stands in for a {@code @PreAuthorize} denial: method security is not active in a
		 * standalone MockMvc setup, but the exception it raises is exactly this one, and what is
		 * under test is how the advice renders it.
		 */
		@PostMapping("/probe/denied")
		void denied() {
			throw new AuthorizationDeniedException("Access Denied for authority USER_READ");
		}
	}
}
