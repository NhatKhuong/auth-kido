package com.example.auth.controller;

import com.example.auth.dto.request.ChangePasswordRequest;
import com.example.auth.dto.response.AccountResponse;
import com.example.auth.security.AuthenticatedUser;
import com.example.auth.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * The caller's own account (architecture 01-overview.md section 5).
 *
 * <p>Authorization is by permission, not by role (section 4), so a role added later reaches these
 * endpoints as data without touching this class.
 *
 * <p>The account is always taken from {@link AuthenticationPrincipal} and never from a path
 * variable or the body: "me" has to mean the authenticated caller, or one user could read or
 * overwrite another's password by changing an id.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

	private final UserService userService;

	public UserController(UserService userService) {
		this.userService = userService;
	}

	/** 200 with the account; 401 without a usable access token; 403 without {@code ACCOUNT_READ}. */
	@GetMapping("/me")
	@PreAuthorize("hasAuthority('ACCOUNT_READ')")
	public AccountResponse currentAccount(@AuthenticationPrincipal AuthenticatedUser principal) {
		return userService.getCurrentAccount(principal.id());
	}

	/**
	 * 204 with no body; 400 if the body is incomplete ({@code VALIDATION_ERROR}) or the current
	 * password is wrong ({@code INVALID_CURRENT_PASSWORD}); 401 without a usable access token; 403
	 * without {@code PASSWORD_CHANGE}.
	 *
	 * <p>204 rather than 200 with the account: there is nothing to return that the caller does not
	 * already have, and an empty body cannot accidentally echo a password.
	 */
	@PutMapping("/me/password")
	@PreAuthorize("hasAuthority('PASSWORD_CHANGE')")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void changePassword(
			@AuthenticationPrincipal AuthenticatedUser principal,
			@Valid @RequestBody ChangePasswordRequest request) {
		userService.changePassword(principal.id(), request);
	}
}
