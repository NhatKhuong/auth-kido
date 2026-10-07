package com.example.auth.service;

import com.example.auth.dto.request.ChangePasswordRequest;
import com.example.auth.dto.response.AccountResponse;
import com.example.auth.dto.response.UserSummaryResponse;
import com.example.auth.exception.InvalidCurrentPasswordException;
import com.example.auth.exception.UnauthorizedException;
import java.util.List;

/**
 * Account use cases of the authenticated caller (architecture 01-overview.md section 2.3).
 *
 * <p>Both operations take the account id rather than an {@code Authentication}: the service layer
 * stays independent of the security layer, and the controller remains the only place that knows
 * how the current caller is identified.
 */
public interface UserService {

	/**
	 * Reads the caller's own account.
	 *
	 * @param userId id carried by the verified access token
	 * @throws UnauthorizedException if no account with that id exists any more
	 */
	AccountResponse getCurrentAccount(Long userId);

	/**
	 * Replaces the caller's password after verifying the one they have now.
	 *
	 * <p>The new password is hashed before it is stored; plaintext never reaches the database.
	 *
	 * @param userId  id carried by the verified access token
	 * @param request current and new password
	 * @throws InvalidCurrentPasswordException if {@code currentPassword} does not match the stored hash
	 * @throws UnauthorizedException           if no account with that id exists any more
	 */
	void changePassword(Long userId, ChangePasswordRequest request);

	/**
	 * Lists every account for an administrator.
	 *
	 * <p>Takes no caller: who may call it is an authorization decision, enforced by the permission
	 * on the controller method, and duplicating that check here would create a second place for the
	 * rule to drift. The returned entries carry no credential material.
	 *
	 * @return one entry per account, oldest first
	 */
	List<UserSummaryResponse> listUsers();
}
