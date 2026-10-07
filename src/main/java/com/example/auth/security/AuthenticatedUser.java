package com.example.auth.security;

/**
 * The principal placed in the {@code SecurityContext} for an authenticated request.
 *
 * <p>It carries the id as well as the username so a handler can act on the current account
 * without querying by username again, and it deliberately holds nothing else: no password hash,
 * no entity, nothing lazy that could be touched outside a transaction.
 *
 * @param id       database id of the account
 * @param username username the access token was issued for
 */
public record AuthenticatedUser(Long id, String username) {

	/** Shown wherever Spring Security logs the principal, so it must stay free of secrets. */
	@Override
	public String toString() {
		return username;
	}
}
