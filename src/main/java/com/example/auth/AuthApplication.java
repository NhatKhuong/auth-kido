package com.example.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;

/**
 * {@link UserDetailsServiceAutoConfiguration} is excluded because, with no {@code UserDetailsService}
 * of our own, it registers an in-memory user with a generated password and logs
 * "This generated password is for development use only" on every start. Nothing can reach it — the
 * filter chain disables HTTP Basic and form login — but it is a second identity source in the
 * context and a startup warning that invites exactly the wrong conclusion. Authentication here is
 * bearer tokens only (security/SecurityConfig).
 */
@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
public class AuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthApplication.class, args);
	}

}
