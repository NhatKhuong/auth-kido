package com.example.auth.exception;

import java.util.List;
import java.util.stream.Collectors;

import com.example.auth.dto.response.ErrorResponse;
import com.example.auth.security.JsonAccessDeniedHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSourceResolvable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/**
 * Turns every exception that reaches the dispatcher into the one error body defined in
 * {@code documents/architecture/01-overview.md} section 7.
 *
 * <p>401 is not produced here: that decision belongs to the security layer and is rendered by the
 * authentication entry point. 403 has two sources and only one of them reaches the filter chain's
 * access denied handler, so the other is mapped here — see
 * {@link #handleAuthorizationDenied(AuthorizationDeniedException)}.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

	private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

	private static final String VALIDATION_ERROR = "VALIDATION_ERROR";
	private static final String MALFORMED_REQUEST = "MALFORMED_REQUEST";
	private static final String INTERNAL_ERROR = "INTERNAL_ERROR";
	/** Shared so an unmatched route and a missing record cannot drift into two 404 codes. */
	private static final String NOT_FOUND = ResourceNotFoundException.CODE;

	/** Failures that already know their own status and code (404, 409, and later 401). */
	@ExceptionHandler(ApiException.class)
	public ResponseEntity<ErrorResponse> handleApiException(ApiException ex) {
		return ResponseEntity.status(ex.getStatus())
				.body(new ErrorResponse(ex.getCode(), ex.getMessage()));
	}

	/**
	 * A {@code @PreAuthorize} denial on a handler method.
	 *
	 * <p>Method security raises it while the dispatcher is invoking the handler method, not inside
	 * {@code AuthorizationFilter}, so the configured {@link JsonAccessDeniedHandler} is not what
	 * answers it. Rendering it where it surfaces is deliberate: the alternative is to rethrow and
	 * rely on the exception travelling back out of the dispatcher to
	 * {@code ExceptionTranslationFilter}, which only happens as long as no {@code @ExceptionHandler}
	 * claims it — too subtle a thing for a 403 to depend on. The code and message are read from that
	 * handler instead of repeated, so the two routes cannot drift apart.
	 *
	 * <p>Only this subtype is handled: a bare {@link AccessDeniedException} is still rethrown by
	 * {@link #handleUnexpected(Exception)} so the filter chain renders it, and both routes end at
	 * the same body.
	 */
	@ExceptionHandler(AuthorizationDeniedException.class)
	public ResponseEntity<ErrorResponse> handleAuthorizationDenied(AuthorizationDeniedException ex) {
		// The exception is not echoed: its message names the authority that was required.
		return ResponseEntity.status(HttpStatus.FORBIDDEN)
				.body(new ErrorResponse(JsonAccessDeniedHandler.CODE, JsonAccessDeniedHandler.MESSAGE));
	}

	/** Bean validation on an {@code @Valid} request body. */
	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<ErrorResponse> handleBodyValidation(MethodArgumentNotValidException ex) {
		String message = ex.getBindingResult().getFieldErrors().stream()
				.map(GlobalExceptionHandler::describe)
				.collect(Collectors.joining("; "));
		return badRequest(VALIDATION_ERROR, message.isEmpty() ? "Request validation failed" : message);
	}

	/** Bean validation on path variables, request params or other handler method arguments. */
	@ExceptionHandler(HandlerMethodValidationException.class)
	public ResponseEntity<ErrorResponse> handleParameterValidation(HandlerMethodValidationException ex) {
		List<? extends MessageSourceResolvable> errors = ex.getAllErrors();
		String message = errors.stream()
				.map(MessageSourceResolvable::getDefaultMessage)
				.filter(text -> text != null && !text.isBlank())
				.collect(Collectors.joining("; "));
		return badRequest(VALIDATION_ERROR, message.isEmpty() ? "Request validation failed" : message);
	}

	/** Body missing or not parsable as JSON. */
	@ExceptionHandler(HttpMessageNotReadableException.class)
	public ResponseEntity<ErrorResponse> handleUnreadableBody(HttpMessageNotReadableException ex) {
		// The exception message can echo the payload, which may contain a password, so it is dropped.
		return badRequest(MALFORMED_REQUEST, "Request body is missing or malformed");
	}

	/** No handler and no static resource matches the requested path. */
	@ExceptionHandler({ NoResourceFoundException.class, NoHandlerFoundException.class })
	public ResponseEntity<ErrorResponse> handleNoHandler(Exception ex) {
		return ResponseEntity.status(HttpStatus.NOT_FOUND)
				.body(new ErrorResponse(NOT_FOUND, "The requested resource was not found"));
	}

	/** Anything unplanned: logged in full, reported without internal detail. */
	@ExceptionHandler(Exception.class)
	public ResponseEntity<ErrorResponse> handleUnexpected(Exception ex) throws Exception {
		// Security decisions must stay with the security layer: swallowing these here would
		// turn an authorization failure raised by method security into a 500.
		if (ex instanceof AuthenticationException || ex instanceof AccessDeniedException) {
			throw ex;
		}
		log.error("Unhandled exception", ex);
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body(new ErrorResponse(INTERNAL_ERROR, "An unexpected error occurred"));
	}

	private static ResponseEntity<ErrorResponse> badRequest(String code, String message) {
		return ResponseEntity.badRequest().body(new ErrorResponse(code, message));
	}

	private static String describe(FieldError error) {
		return error.getField() + ": " + error.getDefaultMessage();
	}
}
