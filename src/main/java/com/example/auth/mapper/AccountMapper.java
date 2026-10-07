package com.example.auth.mapper;

import com.example.auth.dto.response.AccountResponse;
import com.example.auth.dto.response.UserSummaryResponse;
import com.example.auth.entity.Permission;
import com.example.auth.entity.Role;
import com.example.auth.entity.User;
import java.util.Comparator;
import java.util.List;

/**
 * Turns a {@link User} into the response bodies of the user-facing APIs
 * (architecture 01-overview.md section 2.1).
 *
 * <p>An explicit mapper, rather than serialising the entity, is what makes "the response never
 * contains the password hash" a property of the code instead of a thing to remember: a column
 * added to {@link User} later cannot leak into the body without an edit here.
 *
 * <p>Static because it holds no state and depends on nothing; injecting it would only add a mock
 * to every test that needs it.
 */
public final class AccountMapper {

	private AccountMapper() {
	}

	/** Must be called while the roles and permissions of {@code user} are loaded or reachable. */
	public static AccountResponse toAccountResponse(User user) {
		return new AccountResponse(
				user.getId(),
				user.getUsername(),
				// Sorted, because the response is a contract and a Set's iteration order is not:
				// an assertion or a client diff must not depend on how the rows came back.
				user.getRoles().stream().map(Role::getName).sorted(Comparator.naturalOrder()).toList(),
				user.getPermissions().stream().map(Permission::getName).sorted(Comparator.naturalOrder()).toList());
	}

	/**
	 * One entry of the administrative user list.
	 *
	 * <p>Deliberately not {@link #toAccountResponse(User)}: that body is the caller's own account
	 * and includes the permission set. Listing accounts needs neither, so the narrower record keeps
	 * the two contracts independent — widening one later cannot widen the other by accident.
	 *
	 * <p>Must be called while the roles of {@code user} are loaded or reachable.
	 */
	public static UserSummaryResponse toUserSummaryResponse(User user) {
		return new UserSummaryResponse(
				user.getId(),
				user.getUsername(),
				// Sorted for the same reason as in toAccountResponse: a Set's iteration order is
				// not part of the contract, the sorted list is.
				user.getRoles().stream().map(Role::getName).sorted(Comparator.naturalOrder()).toList());
	}

	/** The administrative list body, in the order the repository returned the rows. */
	public static List<UserSummaryResponse> toUserSummaryResponses(List<User> users) {
		return users.stream().map(AccountMapper::toUserSummaryResponse).toList();
	}
}
