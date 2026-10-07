package com.example.auth.service;

import com.example.auth.dto.request.LoginRequest;
import com.example.auth.dto.request.RefreshTokenRequest;
import com.example.auth.dto.response.LoginResponse;
import com.example.auth.exception.InvalidCredentialsException;
import com.example.auth.exception.InvalidRefreshTokenException;

/**
 * Authentication use cases (architecture 01-overview.md section 2.3).
 *
 * <p>An interface at this boundary keeps the controller independent of how tokens are produced,
 * which is what lets the controller be tested as a slice.
 */
public interface AuthenticationService {

	/**
	 * Authenticates a username and password and issues an access token plus a refresh token.
	 *
	 * @throws InvalidCredentialsException if the account does not exist or the password is wrong
	 */
	LoginResponse login(LoginRequest request);

	/**
	 * Exchanges a refresh token for a new access token and a new refresh token.
	 *
	 * <p>The presented token is rotated away: it is single use (ADR 0003), so the response is the
	 * same shape as login and the client must store the returned refresh token in place of the one
	 * it sent.
	 *
	 * @throws InvalidRefreshTokenException if the token is unknown, already rotated, or expired
	 */
	LoginResponse refresh(RefreshTokenRequest request);
}
