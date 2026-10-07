package com.example.auth.security;

import com.example.auth.config.JwtProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

/**
 * The stateless JWT security chain (architecture 01-overview.md sections 2.6, 3 and 4).
 *
 * <p>Replaces the permit-everything placeholder from backlog 0002. Backlog 0007 adds the access
 * denied handler that renders 403 in the same error shape.
 */
@Configuration
// Method security is enabled here rather than in 0007 so the foundation the rest of the epic
// builds on is complete: @PreAuthorize("hasAuthority('USER_READ')") on a later endpoint then
// needs no configuration change.
@EnableMethodSecurity
@EnableConfigurationProperties(JwtProperties.class)
public class SecurityConfig {

	@Bean
	SecurityFilterChain securityFilterChain(
			HttpSecurity http,
			JwtAuthenticationFilter jwtAuthenticationFilter,
			AuthenticationEntryPoint authenticationEntryPoint,
			AccessDeniedHandler accessDeniedHandler) throws Exception {
		return http
				// No cookies or sessions are used, so CSRF tokens have nothing to protect.
				.csrf(csrf -> csrf.disable())
				// Bearer tokens are the only way in; leaving these enabled would add a second,
				// unreviewed authentication path.
				.httpBasic(basic -> basic.disable())
				.formLogin(form -> form.disable())
				.logout(logout -> logout.disable())
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.exceptionHandling(exceptions -> exceptions
						.authenticationEntryPoint(authenticationEntryPoint)
						// 403 in the same error shape as every other failure. Reached when
						// AuthorizationFilter denies a request; a @PreAuthorize denial is raised
						// later, during handler invocation, and is rendered by
						// GlobalExceptionHandler from the same two literals.
						.accessDeniedHandler(accessDeniedHandler))
				.authorizeHttpRequests(requests -> requests
						// Login and refresh must work without an access token: refresh exists
						// precisely because the caller's access token has expired.
						.requestMatchers("/api/auth/**").permitAll()
						// Everything else, including paths that do not exist yet: default-deny
						// means an endpoint added later is protected the moment it appears.
						//
						// Deliberately no per-path authority rule, not even for /api/admin/**:
						// permissions are declared with @PreAuthorize next to the handler method,
						// so authorization cannot be lost by moving a path or adding a route.
						.anyRequest().authenticated())
				// After ExceptionTranslationFilter and before the authorization decision: the
				// SecurityContext must be populated before authorizeHttpRequests is evaluated.
				.addFilterBefore(jwtAuthenticationFilter, AuthorizationFilter.class)
				.build();
	}

	/**
	 * Plain BCrypt, not a {@code DelegatingPasswordEncoder}.
	 *
	 * <p>The seeded hashes (migration V7) are bare {@code $2a$10$...} values without the
	 * {@code {bcrypt}} prefix a delegating encoder requires, so a delegating encoder would reject
	 * every stored password. Changing the hash format later is a migration plus a decision, not a
	 * silent swap here.
	 */
	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
