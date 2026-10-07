package com.example.auth.controller;

import com.example.auth.dto.response.UserSummaryResponse;
import com.example.auth.service.UserService;
import java.util.List;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Administrative view of the accounts (architecture 01-overview.md section 5).
 *
 * <p>The gate is the permission {@code USER_READ}, not the role {@code ROLE_ADMIN} (section 4): the
 * authorities in the {@code SecurityContext} are permission names, so {@code hasRole('ADMIN')}
 * would silently never match — it looks for the {@code ROLE_} prefix this project does not grant —
 * and checking the role would mean editing this class to introduce a MANAGER or AUDITOR later.
 *
 * <p>The check lives on the method and not in the filter chain's URL rules. {@code SecurityConfig}
 * only requires that the request be authenticated; a caller without {@code USER_READ} therefore
 * reaches the handler method and is rejected by method security, which is what makes the rule
 * travel with the code instead of with a path pattern.
 *
 * <p>Separate from {@code UserController}: that class is "the caller's own account" and derives
 * everything from the authenticated principal, while this one reads other people's accounts under
 * a different permission. Keeping them apart stops the two authorization stories from mixing.
 */
@RestController
@RequestMapping("/api/admin/users")
public class AdminUserController {

	private final UserService userService;

	public AdminUserController(UserService userService) {
		this.userService = userService;
	}

	/**
	 * 200 with one entry per account; 401 without a usable access token ({@code UNAUTHORIZED});
	 * 403 for an authenticated caller without {@code USER_READ} ({@code FORBIDDEN}).
	 *
	 * <p>Creating, changing, deleting an account and assigning roles are deliberately absent: this
	 * endpoint is read-only, and {@code USER_MANAGE} is seeded but has no endpoint yet.
	 */
	@GetMapping
	@PreAuthorize("hasAuthority('USER_READ')")
	public List<UserSummaryResponse> listUsers() {
		return userService.listUsers();
	}
}
