package com.example.auth.repository;

import static org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase.Replace.NONE;

import com.example.auth.TestcontainersConfiguration;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.context.annotation.Import;

/**
 * Runs a JPA slice test against the real PostgreSQL started by
 * {@link TestcontainersConfiguration}, with Flyway applied.
 *
 * <p>{@code @DataJpaTest} would otherwise swap in an embedded database; there is none on the
 * classpath, and swapping would in any case test a different database than the one that ships.
 * {@code replace = NONE} keeps the container's datasource, which is the whole point: the seed data
 * and the {@code ddl-auto: validate} mapping only mean something on PostgreSQL.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@DataJpaTest
@AutoConfigureTestDatabase(replace = NONE)
@Import(TestcontainersConfiguration.class)
public @interface DataJpaOnPostgres {
}
