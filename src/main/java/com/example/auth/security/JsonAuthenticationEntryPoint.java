package com.example.auth.security;

import com.example.auth.dto.response.ErrorResponse;
import com.example.auth.exception.UnauthorizedException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * Turns every unauthenticated request into the project's single error body
 * (architecture 01-overview.md section 7) instead of Spring Security's default HTML or empty 401.
 *
 * <p>This is the one place where an {@code AuthenticationException} becomes a response, which is
 * why {@code GlobalExceptionHandler} rethrows those rather than mapping them itself.
 */
@Component
public class JsonAuthenticationEntryPoint implements AuthenticationEntryPoint {

	/** Shared with {@link UnauthorizedException} so the two cannot drift apart. */
	static final String CODE = UnauthorizedException.CODE;

	/**
	 * One message for every cause. Saying which of "missing", "malformed", "wrongly signed" or
	 * "expired" applied would tell an attacker which of their guesses was closer.
	 */
	static final String MESSAGE = "Access token is missing, invalid or expired";

	private final ObjectMapper objectMapper;

	public JsonAuthenticationEntryPoint(ObjectMapper objectMapper) {
		this.objectMapper = objectMapper;
	}

	@Override
	public void commence(
			HttpServletRequest request,
			HttpServletResponse response,
			AuthenticationException authException) throws IOException {
		// The exception is not echoed: its message can contain the rejected token.
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		objectMapper.writeValue(response.getOutputStream(), new ErrorResponse(CODE, MESSAGE));
	}
}
