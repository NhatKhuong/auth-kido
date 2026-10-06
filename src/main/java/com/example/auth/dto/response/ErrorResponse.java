package com.example.auth.dto.response;

/**
 * The single error body every failing API call returns.
 *
 * <p>Shape and the HTTP status each error maps to are a system contract:
 * see {@code documents/architecture/01-overview.md} section 7.
 *
 * @param code    stable machine-readable identifier in UPPER_SNAKE_CASE
 * @param message human-readable explanation, safe to show to a client
 */
public record ErrorResponse(String code, String message) {
}
