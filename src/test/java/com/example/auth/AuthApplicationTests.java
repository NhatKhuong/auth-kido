package com.example.auth;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

/**
 * Boots the whole application: proves the datasource, Flyway and Hibernate
 * {@code ddl-auto: validate} wiring actually agree with each other.
 *
 * <p>The PostgreSQL it runs against is started by {@link TestcontainersConfiguration}, so this
 * needs a Docker daemon but not a running docker-compose stack.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
class AuthApplicationTests {

	@Test
	void contextLoads() {
	}

}
