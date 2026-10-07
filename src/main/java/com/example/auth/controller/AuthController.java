package com.example.auth.controller;

import com.example.auth.dto.request.LoginRequest;
import com.example.auth.dto.request.RefreshTokenRequest;
import com.example.auth.dto.response.LoginResponse;
import com.example.auth.service.AuthenticationService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Authentication endpoints (architecture 01-overview.md section 5). */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

	private final AuthenticationService authenticationService;

	public AuthController(AuthenticationService authenticationService) {
		this.authenticationService = authenticationService;
	}

	/** 200 with tokens; 400 if the body is incomplete; 401 if the credentials are rejected. */
	@PostMapping("/login")
	public LoginResponse login(@Valid @RequestBody LoginRequest request) {
		return authenticationService.login(request);
	}

	/**
	 * 200 with a new access token and a new refresh token; 400 if the body is incomplete; 401 if
	 * the presented token is unknown, already rotated, or expired.
	 *
	 * <p>The response is the same shape as login because the refresh token rotates on every use
	 * (ADR 0003) — the client replaces the token it sent with the one it gets back.
	 */
	@PostMapping("/refresh")
	public LoginResponse refresh(@Valid @RequestBody RefreshTokenRequest request) {
		return authenticationService.refresh(request);
	}
}
