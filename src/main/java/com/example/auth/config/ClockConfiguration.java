package com.example.auth.config;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Makes "now" an injected dependency.
 *
 * <p>Token issuing and expiry are time arithmetic, which is exactly the kind of logic that is
 * untestable when every component calls {@code Instant.now()} itself: a test would have to wait
 * for real time to pass to observe an expired token. With a {@link Clock} bean a test can hand in
 * a fixed instant and assert exact values.
 */
@Configuration
public class ClockConfiguration {

	@Bean
	Clock clock() {
		// UTC, not the system zone: stored timestamps are TIMESTAMPTZ / Instant, so the server's
		// local zone must never influence when a token expires.
		return Clock.systemUTC();
	}
}
