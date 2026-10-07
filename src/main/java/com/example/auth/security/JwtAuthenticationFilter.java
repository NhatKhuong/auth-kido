package com.example.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates a request from its {@code Authorization: Bearer <accessToken>} header
 * (architecture 01-overview.md section 2.6).
 *
 * <p>The principal is built from the token's claims, never from a database lookup: that is what
 * makes the API stateless, and it is why the token carries the user id and the permission names.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private static final String BEARER_PREFIX = "Bearer ";

	private final JwtService jwtService;
	private final AuthenticationEntryPoint authenticationEntryPoint;

	public JwtAuthenticationFilter(JwtService jwtService, AuthenticationEntryPoint authenticationEntryPoint) {
		this.jwtService = jwtService;
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	@Override
	protected void doFilterInternal(
			HttpServletRequest request,
			HttpServletResponse response,
			FilterChain filterChain) throws ServletException, IOException {
		String header = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (header == null || !header.startsWith(BEARER_PREFIX)) {
			// No bearer token: stay anonymous and let the authorization rules decide. A public
			// endpoint such as /api/auth/login must still work without a token.
			filterChain.doFilter(request, response);
			return;
		}

		Authentication authentication;
		try {
			authentication = toAuthentication(jwtService.verify(header.substring(BEARER_PREFIX.length()).trim()));
		}
		// AuthenticationException is caught here too: this filter runs after
		// ExceptionTranslationFilter, so anything it throws would reach the container as a 500
		// instead of the entry point.
		catch (JwtException | AuthenticationException ex) {
			// A token that was presented and rejected is answered immediately rather than
			// downgraded to anonymous: otherwise an expired token on a public endpoint would look
			// like success, and the client would never learn it has to refresh.
			SecurityContextHolder.clearContext();
			authenticationEntryPoint.commence(request, response, new BadCredentialsException("Invalid access token"));
			return;
		}

		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(authentication);
		SecurityContextHolder.setContext(context);
		try {
			filterChain.doFilter(request, response);
		}
		finally {
			// Nothing is persisted between requests, so the context must not outlive this one on a
			// pooled container thread.
			SecurityContextHolder.clearContext();
		}
	}

	private static Authentication toAuthentication(Jwt jwt) {
		Object userId = jwt.getClaim(JwtService.CLAIM_USER_ID);
		if (!(userId instanceof Number number) || jwt.getSubject() == null) {
			throw new BadCredentialsException("Access token is missing required claims");
		}
		AuthenticatedUser principal = new AuthenticatedUser(number.longValue(), jwt.getSubject());
		// Credentials are null on purpose: no password or token value is kept in the context.
		return UsernamePasswordAuthenticationToken.authenticated(principal, null, authorities(jwt));
	}

	private static List<GrantedAuthority> authorities(Jwt jwt) {
		List<String> names = jwt.getClaimAsStringList(JwtService.CLAIM_AUTHORITIES);
		if (names == null) {
			return List.of();
		}
		return names.stream().map(SimpleGrantedAuthority::new).map(GrantedAuthority.class::cast).toList();
	}
}
