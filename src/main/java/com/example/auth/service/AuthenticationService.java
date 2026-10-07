package com.example.auth.service;

import com.example.auth.dto.request.LoginRequest;
import com.example.auth.dto.response.LoginResponse;
import com.example.auth.exception.InvalidCredentialsException;

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
}
