package com.example.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body of {@code PUT /api/users/me/password} (architecture 01-overview.md sections 5 and 7).
 *
 * <p>A missing, blank or too short field is a 400 {@code VALIDATION_ERROR}, not a rejected
 * password: the request never reached the point where the current password could be judged. Only a
 * minimum length is enforced — a full strength policy is out of scope for backlog 0006.
 *
 * @param currentPassword plaintext password the account has now, verified and then discarded
 * @param newPassword     plaintext replacement, hashed before it is stored
 */
public record ChangePasswordRequest(
		@NotBlank(message = "currentPassword is required") String currentPassword,
		@NotBlank(message = "newPassword is required")
		@Size(
				min = MIN_NEW_PASSWORD_LENGTH,
				max = MAX_NEW_PASSWORD_LENGTH,
				message = "newPassword must be between " + MIN_NEW_PASSWORD_LENGTH + " and "
						+ MAX_NEW_PASSWORD_LENGTH + " characters")
		String newPassword) {

	/** Basic floor only; the ticket's non-goals exclude a composition policy. */
	public static final int MIN_NEW_PASSWORD_LENGTH = 8;

	/**
	 * BCrypt hashes only the first 72 bytes of its input, so anything beyond that is silently
	 * ignored rather than stored. Rejecting it is honest; accepting it would let a caller believe a
	 * 200-character password was kept.
	 */
	public static final int MAX_NEW_PASSWORD_LENGTH = 72;

	/** Omits both passwords: request objects end up in debug logs and exception messages. */
	@Override
	public String toString() {
		return "ChangePasswordRequest{}";
	}
}
