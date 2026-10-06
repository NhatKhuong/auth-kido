package com.example.auth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * PLACEHOLDER security configuration — replaced by backlog 0004.
 *
 * <p>It exists only so the application starts as a usable API: without an explicit chain,
 * Spring Boot secures every path with generated-password HTTP Basic, which would block the
 * scaffold before any endpoint exists.
 *
 * <p>It authorizes every request, so nothing may be built on top of it. Backlog 0004 replaces
 * it with the real stateless JWT chain (JWT filter, {@code /api/auth/**} open, everything else
 * authenticated, JSON 401 entry point) and backlog 0007 adds the 403 access denied handler.
 */
@Configuration
public class SecurityConfig {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http
				// No cookies or sessions are used, so CSRF tokens have nothing to protect.
				.csrf(csrf -> csrf.disable())
				.httpBasic(basic -> basic.disable())
				.formLogin(form -> form.disable())
				.logout(logout -> logout.disable())
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(requests -> requests.anyRequest().permitAll())
				.build();
	}
}
