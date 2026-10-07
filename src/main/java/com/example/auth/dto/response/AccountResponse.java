package com.example.auth.dto.response;

import java.util.List;

/**
 * Body of {@code GET /api/users/me} (architecture 01-overview.md sections 5 and 7).
 *
 * <p>The field set is a contract and is deliberately closed: {@code password},
 * {@code passwordHash}, {@code refreshToken} and {@code tokenHash} must never appear here, which
 * is why this record is built from a mapper instead of serialising the entity.
 *
 * @param id          database id of the account
 * @param username    username the caller authenticated as
 * @param roles       role names held by the account, sorted for a stable response
 * @param permissions permissions granted through those roles, flattened and sorted
 */
public record AccountResponse(
		Long id,
		String username,
		List<String> roles,
		List<String> permissions) {
}
