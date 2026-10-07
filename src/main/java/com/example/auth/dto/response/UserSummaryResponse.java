package com.example.auth.dto.response;

import java.util.List;

/**
 * One entry of {@code GET /api/admin/users} (architecture 01-overview.md sections 5 and 7).
 *
 * <p>The field set is a contract and is deliberately narrower than {@link AccountResponse}: an
 * administrator listing accounts has no need for another user's permission set, and
 * {@code password}, {@code passwordHash}, {@code refreshToken} and {@code tokenHash} must never
 * appear here. That is why the list is built by a mapper instead of serialising the entity — a
 * column added to {@code User} later cannot leak into this body without an edit.
 *
 * @param id       database id of the account
 * @param username username of the account
 * @param roles    role names held by the account, sorted for a stable response
 */
public record UserSummaryResponse(
		Long id,
		String username,
		List<String> roles) {
}
