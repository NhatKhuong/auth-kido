package com.example.auth;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

/**
 * Boots the whole application: proves the datasource, Flyway and Hibernate
 * {@code ddl-auto: validate} wiring actually agree with each other.
 *
 * <p>The PostgreSQL it runs against is started by {@link TestcontainersConfiguration}, so this
 * needs a Docker daemon but not a running docker-compose stack.
 *
 * <p>The {@code test} profile supplies a signing key (application-test.yml). Since backlog 0004 the
 * application refuses to start without one, so this test also shows that a configured key is all
 * that is needed to boot.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
class AuthApplicationTests {

	@Test
	void contextLoads() {
	}

}
