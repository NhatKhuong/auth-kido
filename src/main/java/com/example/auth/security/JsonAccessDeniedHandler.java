package com.example.auth.security;

import com.example.auth.dto.response.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * Turns an authorization failure into the project's single error body
 * (architecture 01-overview.md section 7) instead of Spring Security's default HTML 403.
 *
 * <p>This handler covers the denials raised inside the filter chain, by
 * {@code AuthorizationFilter}. A denial from {@code @PreAuthorize} happens later, while the
 * dispatcher is invoking the handler method, and is rendered by {@code GlobalExceptionHandler}
 * instead — which is why {@link #CODE} and {@link #MESSAGE} are public: both paths must produce
 * the identical body, and sharing the literals is what guarantees it.
 *
 * <p>Counterpart of {@link JsonAuthenticationEntryPoint}: that one answers "we do not know who you
 * are" with 401, this one answers "we know who you are and it is not enough" with 403.
 */
@Component
public class JsonAccessDeniedHandler implements AccessDeniedHandler {

	/** Literal fixed by the API contract; {@code GlobalExceptionHandler} renders the same one. */
	public static final String CODE = "FORBIDDEN";

	/**
	 * One message for every denial. Naming the permission that was missing would hand an attacker a
	 * map of the authorization model, and the caller cannot grant it to themselves anyway.
	 */
	public static final String MESSAGE = "You do not have permission to perform this action";

	private final ObjectMapper objectMapper;

	public JsonAccessDeniedHandler(ObjectMapper objectMapper) {
		this.objectMapper = objectMapper;
	}

	@Override
	public void handle(
			HttpServletRequest request,
			HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException {
		// The exception is not echoed: its message names the authority that was required.
		response.setStatus(HttpServletResponse.SC_FORBIDDEN);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		objectMapper.writeValue(response.getOutputStream(), new ErrorResponse(CODE, MESSAGE));
	}
}
