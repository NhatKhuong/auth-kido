package com.example.auth;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Database for integration tests.
 *
 * <p>The container is started by the test run itself, so {@code ./mvnw verify} is green on a
 * clean machine without anyone remembering to bring docker-compose up first. It is still a real
 * PostgreSQL, so Flyway and Hibernate {@code ddl-auto: validate} are exercised for real.
 *
 * <p>{@link ServiceConnection} overrides {@code spring.datasource.*} at runtime, so the
 * development defaults in application.yml are ignored here and tests never touch the
 * docker-compose database.
 *
 * <p>Keep the image tag in step with docker-compose.yml: tests and development should not run
 * against different PostgreSQL versions.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfiguration {

	static final String POSTGRES_IMAGE = "postgres:18.6-alpine";

	@Bean
	@ServiceConnection
	PostgreSQLContainer postgresContainer() {
		return new PostgreSQLContainer(POSTGRES_IMAGE);
	}
}
